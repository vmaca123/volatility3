"""Collects the page file slots named by OriginalPte in the PFN database and matches them with the slots named by process PTEs.

Some PTEs with PageFileAllocated clear name a slot that the AllocationBitmap marks as used, while no PTE with the bit set
names it in the walk. If the owner of such a slot is a page that is now in memory (active, standby or modified list),
that page's _MMPFN.OriginalPte should hold the slot. This counts that.

- Reads the whole _MMPFN array from PFN 0 to the last physical page, and uses entries whose u3.e1.PageLocation is
  standby (2), modified (3), modified no-write (4), active (6) or transition (7).
- If OriginalPte is a software PTE (valid, prototype and transition bits clear) and PageFileHigh is neither 0 nor all ones,
  collects (number, slot), decoded with rule M.
- Joins them by slot with the pagefile.sys PTEs inside VADs from pte_swizzle_probe.py's raw output (.entries.json).
Usage: PYTHONPATH=<vol3 checkout> python pfn_original_pte_slots.py <memory> <probe .entries.json> <out json>
"""
import bisect
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, plugins
from volatility3.plugins.windows import pslist

IN_USE = {2: "standby", 3: "modified", 4: "modified_no_write", 6: "active", 7: "transition"}
LOOKUP_NEEDED = 0xFFFFFFFF


def member(t, name):
    """(offset, subtype) of a member; bitfields give (offset, start_bit, length)."""
    off, sub = t.vol.members[name]
    return off, sub


def main():
    mem, entries_path, out = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3])
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    dump = json.load(open(entries_path, encoding="utf-8"))
    sw = probe["mmpte_software"]
    low, alloc = sw["PageFileLow"]["start"], sw["PageFileAllocated"]["start"]
    swz = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    size = probe["paging_files"]["0"]["size_pages"]
    bm = bytes.fromhex(dump["bitmaps"]["0"])

    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = mem.as_uri()
    ams = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    plug = plugins.construct_plugin(ctx, ams, pslist.PsList, "plugins.PsList", None, None)
    kernel = ctx.modules[plug.config["kernel"]]
    klayer = ctx.layers[kernel.layer_name]

    pfn_t = kernel.get_type("_MMPFN")
    entry_size = pfn_t.size
    orig_off, _ = member(pfn_t, "OriginalPte")
    u3_off, u3 = member(pfn_t, "u3")
    u3 = ctx.symbol_space.get_type(u3.vol.type_name)
    e1_off, e1 = member(u3, "e1")
    e1 = ctx.symbol_space.get_type(e1.vol.type_name)
    loc_off, loc = member(e1, "PageLocation")
    loc_byte = u3_off + e1_off + loc_off
    loc_start, loc_len = loc.vol.start_bit, loc.vol.end_bit - loc.vol.start_bit
    base = kernel.object("pointer", offset=kernel.get_symbol("MmPfnDatabase").address)
    base = int(base)
    # Windows 10 kernels have no MmHighestPhysicalPage symbol, so the last PFN comes from the end of the physical layer
    highest = ctx.layers[klayer.config["memory_layer"]].maximum_address >> 12

    def decode(e):
        high = e >> 32
        if e & 1 or e & (1 << 10) or e & (1 << 11) or high in (0, LOOKUP_NEEDED):
            return None
        slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
        return (e >> low) & 0xF, slot, (e >> alloc) & 1

    pfn_slots = defaultdict(list)                     # slot -> [(pfn, location, allocated bit of OriginalPte)]
    stat = Counter()
    chunk = 4096
    for first in range(0, highest + 1, chunk):
        count = min(chunk, highest + 1 - first)
        raw = klayer.read(base + first * entry_size, count * entry_size, pad=True)
        for i in range(count):
            rec = raw[i * entry_size:(i + 1) * entry_size]
            location = (rec[loc_byte] >> loc_start) & ((1 << loc_len) - 1)
            if location not in IN_USE:
                continue
            stat[f"pfn_{IN_USE[location]}"] += 1
            orig, = struct.unpack_from("<Q", rec, orig_off)
            d = decode(orig)
            if d is None:
                continue
            number, slot, a = d
            stat[f"original_pte_page_file_{number}_allocated_{a}"] += 1
            if number == 0:
                pfn_slots[slot].append((first + i, IN_USE[location], a))

    vads = {int(k): sorted(v) for k, v in dump["vads"].items()}
    starts = {p: [x for x, _ in v] for p, v in vads.items()}

    def in_vad(pid, va):
        i = bisect.bisect_right(starts.get(pid, []), va) - 1
        return i >= 0 and vads[pid][i][0] <= va <= vads[pid][i][1]

    ptes = defaultdict(list)                          # slot -> [PageFileAllocated bits]
    rows = []
    for pid, va, e in dump["entries"]:
        high = e >> 32
        if high == LOOKUP_NEEDED or (e >> low) & 0xF or not in_vad(pid, va):
            continue
        slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
        if slot == 0 or slot >= size:
            continue
        a = (e >> alloc) & 1
        ptes[slot].append(a)
        rows.append((slot, a))
    join = Counter()
    join_pfn = Counter()                              # list state and OriginalPte bit of PFN entries on those slots
    no_owner_slots = {"pfn_original_pte_bit_1": set(), "none": set()}   # slot lists that slot_owner_scan.py splits on
    for slot, a in rows:
        used = bool(bm[slot >> 3] & (1 << (slot & 7)))
        set_owner = sum(1 for x in ptes[slot] if x == 1) - (1 if a == 1 else 0) > 0
        pfn = pfn_slots.get(slot, [])
        pfn_a1 = any(x[2] == 1 for x in pfn)
        if a == 1:
            kind = "allocated_1"
        elif not used:
            kind = "allocated_0__slot_free"
        elif set_owner:
            kind = "allocated_0__slot_used__named_by_a_pte_with_bit_set"
        else:
            kind = "allocated_0__slot_used__no_pte_with_bit_set"
        join[f"{kind}__pfn_original_pte_on_slot_{bool(pfn)}" + ("_with_bit_set" if pfn_a1 else "")] += 1
        if kind == "allocated_0__slot_used__no_pte_with_bit_set":
            no_owner_slots["pfn_original_pte_bit_1" if pfn_a1 else "none"].add(slot)
        for _, location, pa in pfn:
            join_pfn[f"{kind}__pfn_{location}_bit_{pa}"] += 1
    report = {"image": str(mem), "mmpfn_size": entry_size, "highest_pfn": highest,
              "pfn": dict(sorted(stat.items())), "pagefile_sys_ptes_by_kind": dict(sorted(join.items())),
              "pfn_entries_on_those_slots": dict(sorted(join_pfn.items())),
              "bit_clear_used_no_process_owner_slots": {k: sorted(v) for k, v in no_owner_slots.items()},
              "slots_in_pfn_original_ptes": len(pfn_slots)}
    out.write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
