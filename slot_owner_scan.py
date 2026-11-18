"""Searches all of physical memory and the page file for the owner of slots named by bit-clear PTEs (a value shaped like a software PTE with PageFileAllocated set and that slot).

Some PTEs with PageFileAllocated clear name a slot that is used in the AllocationBitmap, while neither a walked process PTE
nor a PFN OriginalPte with the bit set names it (see pfn_original_pte_slots.py). Prototype PTEs, kernel-space PTEs, page
tables below transition upper-level entries and page tables in the page file are not walked, so this scans raw bytes.

- Slot groups: no owner found (bit clear, slot used, no process PTE with the bit set; split by whether a PFN OriginalPte
  with the bit set names it), control 1: slots named by a walked process PTE with the bit set (same number, random) - the
  PTE itself should be found in memory, control 2: free slots in the AllocationBitmap (same number, random) - chance matches.
- Value searched: 8-byte aligned; valid, prototype and transition bits clear; page file number 0; non-zero protection;
  PageFileAllocated set; PageFileHigh (rule M) = the slot.
- Scanned: the whole physical layer of the dump (Volatility memory layer), with hits split into inside / outside the PFN
  database, and the whole pagefile.sys.
Usage: PYTHONPATH=<vol3 checkout> python slot_owner_scan.py <memory> <pagefile.sys> <probe .entries.json> <pfn_original_pte_slots out json> <out json>
"""
import bisect
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, plugins
from volatility3.plugins.windows import pslist

CHUNK = 64 << 20


def main():
    mem, pagefile, entries_path, pfn_path, out = sys.argv[1:6]
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    dump = json.load(open(entries_path, encoding="utf-8"))
    sw = probe["mmpte_software"]
    low, alloc = sw["PageFileLow"]["start"], sw["PageFileAllocated"]["start"]
    swz = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    size = probe["paging_files"]["0"]["size_pages"]
    bm = bytes.fromhex(dump["bitmaps"]["0"])
    vads = {int(k): sorted(v) for k, v in dump["vads"].items()}
    starts = {p: [x for x, _ in v] for p, v in vads.items()}

    def in_vad(pid, va):
        i = bisect.bisect_right(starts.get(pid, []), va) - 1
        return i >= 0 and vads[pid][i][0] <= va <= vads[pid][i][1]

    def used(slot):
        return bool(bm[slot >> 3] & (1 << (slot & 7)))

    # walked pagefile.sys PTEs inside VADs: slot -> list of PageFileAllocated bits
    on_slot = defaultdict(list)
    for pid, va, e in dump["entries"]:
        high = e >> 32
        if high == 0xFFFFFFFF or (e >> low) & 0xF or not in_vad(pid, va):
            continue
        slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
        if 0 < slot < size:
            on_slot[slot].append((e >> alloc) & 1)
    # split bit-clear, used slots with no process owner by whether pfn_original_pte_slots.py found a PFN OriginalPte owner
    pfn = json.load(open(pfn_path, encoding="utf-8"))["bit_clear_used_no_process_owner_slots"]
    no_owner = sorted(s for s, bits in on_slot.items() if 0 in bits and 1 not in bits and used(s))
    assert set(no_owner) == set(pfn["pfn_original_pte_bit_1"]) | set(pfn["none"])
    rng = random.Random(20261118)
    owned = sorted(rng.sample(sorted(s for s, bits in on_slot.items() if 1 in bits), len(no_owner)))
    free = []
    while len(free) < len(no_owner):
        s = rng.randrange(1, size)
        if not used(s) and s not in on_slot:
            free.append(s)
    groups = {"bit_clear_used_no_owner_found_yet": sorted(pfn["none"]),
              "bit_clear_used_pfn_original_pte_owner": sorted(pfn["pfn_original_pte_bit_1"]),
              "control_owned_by_process_pte": owned, "control_free_slot": sorted(free)}
    target = np.array(sorted(set(no_owner) | set(owned) | set(free)), dtype=np.uint64)

    def scan(read, total, where):
        found = defaultdict(Counter)                       # slot -> {where: count}
        pos = 0
        while pos < total:
            n = min(CHUNK, total - pos)
            raw = read(pos, n)
            if raw is None:
                pos += n
                continue
            q = np.frombuffer(raw[: len(raw) // 8 * 8], dtype=np.uint64)
            ok = ((q & np.uint64(1)) == 0) & (((q >> np.uint64(10)) & np.uint64(3)) == 0)
            ok &= ((q >> np.uint64(low)) & np.uint64(0xF)) == 0
            ok &= ((q >> np.uint64(5)) & np.uint64(0x1F)) != 0
            ok &= ((q >> np.uint64(alloc)) & np.uint64(1)) == 1
            high = q >> np.uint64(32)
            if swz is not None:
                sbit = (q >> np.uint64(swz)) & np.uint64(1)
                high = np.where(sbit == 1, high, high & np.uint64(~mask_hi & 0xFFFFFFFF))
            ok &= np.isin(high, target)
            for idx in np.nonzero(ok)[0]:
                place = where
                if where == "memory" and pfn_pages is not None:
                    # inside or outside the PFN database (an OriginalPte there may be stale)
                    place = "memory_pfn_database" if ((pos + int(idx) * 8) >> 12) in pfn_pages else "memory_elsewhere"
                found[int(high[idx])][place] += 1
            pos += n
        return found

    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = Path(mem).resolve().as_uri()
    ams = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    plug = plugins.construct_plugin(ctx, ams, pslist.PsList, "plugins.PsList", None, None)
    kernel = ctx.modules[plug.config["kernel"]]
    klayer = ctx.layers[kernel.layer_name]
    phys = ctx.layers[klayer.config["memory_layer"]]
    # physical pages holding the PFN database (virtual range translated page by page)
    pfn_base = int(kernel.object("pointer", offset=kernel.get_symbol("MmPfnDatabase").address))
    pfn_size = kernel.get_type("_MMPFN").size * ((phys.maximum_address >> 12) + 1)
    pfn_pages = set()
    for va in range(pfn_base & ~0xFFF, pfn_base + pfn_size, 0x1000):
        try:
            pa, _, _ = klayer._translate(va)
            pfn_pages.add(pa >> 12)
        except Exception:
            pass
    found_mem = scan(lambda p, n: phys.read(p, n, pad=True), phys.maximum_address + 1, "memory")
    pf = open(pagefile, "rb")
    pf_size = Path(pagefile).stat().st_size

    def read_pf(p, n):
        pf.seek(p)
        return pf.read(n)

    found_pf = scan(read_pf, pf_size, "pagefile")
    report = {"image": mem, "page_file_allocated_bit": alloc, "page_file_low_bit": low, "groups": {}}
    for name, slots in groups.items():
        c = Counter()
        for s in slots:
            m, p = found_mem.get(s, {}), found_pf.get(s, {})
            # control 1 finds the walked PTE itself once in memory, so subtract it to count other places
            own = sum(1 for b in on_slot.get(s, []) if b == 1)
            mem_hits = sum(m.values())
            elsewhere = m.get("memory_elsewhere", 0) - own        # walked PTEs live in page tables, so they are subtracted from the outside-PFN-database count
            in_pfn = m.get("memory_pfn_database", 0)
            c["slots"] += 1
            c["found_in_memory"] += mem_hits > 0
            c["found_in_memory_beyond_walked_ptes"] += mem_hits - own > 0
            c["found_in_pfn_database"] += in_pfn > 0
            c["found_in_memory_outside_pfn_database_beyond_walked_ptes"] += elsewhere > 0
            c["found_only_in_pfn_database"] += in_pfn > 0 and elsewhere <= 0 and sum(p.values()) == 0
            c["found_in_pagefile"] += sum(p.values()) > 0
            c["found_anywhere_beyond_walked_ptes"] += (mem_hits - own > 0) or sum(p.values()) > 0
            c["found_outside_pfn_database_beyond_walked_ptes"] += elsewhere > 0 or sum(p.values()) > 0
        report["groups"][name] = dict(c)
    report["no_owner_slots_found"] = {str(s): {"memory": sum(found_mem.get(s, {}).values()),
                                               "pagefile": sum(found_pf.get(s, {}).values())}
                                      for s in groups["bit_clear_used_no_owner_found_yet"]}
    Path(out).write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in report.items() if k != "no_owner_slots_found"}, indent=1))


if __name__ == "__main__":
    main()
