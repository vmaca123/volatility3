"""Collect paged-out (software) PTEs on Windows x64 directly from the page tables, and test which way of decoding the page file offset is right.

Volatility's address translation code is not used. Kernel symbols are used only to read structure values; the page tables are walked directly on the physical layer.

What is collected
  - Kernel values: MiState.Hardware.InvalidPteMask, the _MMPTE_SOFTWARE bit layout, the page file list (number, size, allocation bitmap)
  - For each process, every PTE in user space (PML4 0-255) that is non-zero and not valid, transition or prototype.
    Only page tables whose upper levels (PML4E, PDPTE, PDE) are all hardware-valid are counted. Below upper levels in transition state,
    an earlier run gave data-like values for PID 4 (page file numbers 3-15, beyond file size), so those are only counted separately.

Four decodings (the page file number is read from the PDB's PageFileLow position, except for V)
  M  MemProcFS: if SwizzleBit is 0, clear the upper 32 bits of the mask from PageFileHigh; if 1, keep it as is
  F  ptenum (Frank Block): always clear the mask bits
  X  PR #778: always XOR with the mask
  V  Volatility 2.28.2: do not clear the mask; the number is bits 1-4

Checks (based on kernel data)
  - Allocation bitmap: a correctly decoded offset must be set in that page file's AllocationBitmap
  - Overlap: two process PTEs must not point to the same (file, offset) (shared memory goes through prototype PTEs, so it is not here)
Usage: pte_swizzle_probe.py <memory.mem> <output json>
"""
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, exceptions, plugins
from volatility3.plugins.windows import pslist

PFN_MASK = ((1 << 45) - 1) & ~0xFFF          # bits 12-44 (same range as Volatility's Windows x64 _maxphyaddr of 45)
PAE_PFN_MASK = ((1 << 52) - 1) & ~0xFFF      # physical address bits 12-51 of a PAE entry
LOOKUP_NEEDED = 0xFFFFFFFF


def bitfield(t, name):
    child = t.vol.members[name][1]
    return child.vol.start_bit, child.vol.end_bit - child.vol.start_bit


def main():
    mem, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = mem.as_uri()
    ams = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    plug = plugins.construct_plugin(ctx, ams, pslist.PsList, "plugins.PsList", None, None)
    kernel = ctx.modules[plug.config["kernel"]]
    klayer = ctx.layers[kernel.layer_name]
    phys = ctx.layers[klayer.config["memory_layer"]]

    sw = kernel.get_type("_MMPTE_SOFTWARE")
    layout = {n: bitfield(sw, n) for n in sw.vol.members}
    low_shift = layout["PageFileLow"][0]
    # Kernels before 1803 (e.g. a Windows Server 2012 R2 image) have no SwizzleBit or InvalidPteMask. Then always treat it as "not swizzled"
    swz_bit = layout["SwizzleBit"][0] if "SwizzleBit" in layout else 63
    try:
        mi_state = kernel.object("_MI_SYSTEM_INFORMATION", offset=kernel.get_symbol("MiState").address)
        invalid_pte_mask = int(mi_state.Hardware.InvalidPteMask)
    except (AttributeError, exceptions.SymbolError, exceptions.InvalidAddressException):
        invalid_pte_mask = 0
    if "SwizzleBit" not in layout:
        invalid_pte_mask = 0
    mask_hi = invalid_pte_mask >> 32

    paging = {}
    try:
        part = kernel.object("_MI_PARTITION", offset=kernel.get_symbol("MiSystemPartition").address)
        paging_count = int(part.Vp.NumberOfPagingFiles)
    except (AttributeError, exceptions.SymbolError, exceptions.InvalidAddressException):
        paging_count = 0                            # if the page file list cannot be read, the bitmap check stays empty
    for i in range(paging_count):
        pf = part.Vp.PagingFile[i].dereference()
        number = int(pf.PageFileNumber)
        bm = pf.Bitmaps.dereference().AllocationBitmap
        nbits = int(bm.SizeOfBitMap)
        try:
            raw = klayer.read(int(bm.Buffer), (nbits + 7) // 8, pad=False)
        except exceptions.InvalidAddressException:
            raw = None
        try:
            name = pf.PageFileName.get_string()
        except exceptions.InvalidAddressException:
            name = None
        paging[number] = {"name": name, "size_pages": int(pf.Size), "virtual_store": int(pf.VirtualStorePagefile),
                          "bitmap_bits": nbits, "bitmap_read": raw is not None,
                          "bitmap_set": sum(bin(b).count("1") for b in raw) if raw else None, "_raw": raw}

    def allocated(number, slot):
        p = paging.get(number)
        if p is None or p["_raw"] is None or slot >= p["bitmap_bits"]:
            return None
        return bool(p["_raw"][slot >> 3] & (1 << (slot & 7)))

    entries = []                                   # (pid, va, pte)
    vads = {}                                      # pid -> [(start, end)]
    walked = Counter()
    for proc in pslist.PsList.list_processes(ctx, plug.config["kernel"]):
        pid = int(proc.UniqueProcessId)
        try:
            proc_layer = ctx.layers[proc.add_process_layer()]
        except exceptions.InvalidAddressException:
            walked["no_process_layer"] += 1
            continue
        # Also walk 32-bit PAE layers (3 levels, PDPT of 4 entries, 32-byte aligned)
        pae = type(proc_layer).__name__.endswith("PAE")
        dtb = proc_layer.config["page_map_offset"] & (~0x1F if pae else PFN_MASK)
        try:
            pml4 = phys.read(dtb, 32 if pae else 0x1000)
        except exceptions.InvalidAddressException:
            walked["pml4_unreadable"] += 1
            continue
        walked["processes_pae" if pae else "processes"] += 1
        ranges = []
        try:
            for vad in proc.get_vad_root().traverse():
                ranges.append((int(vad.get_start()), int(vad.get_end())))
        except exceptions.InvalidAddressException:
            walked["vad_walk_failed"] += 1
        vads[pid] = sorted(ranges)

        def usable(e):
            return bool(e & 1) or (bool(e & (1 << 11)) and not e & (1 << 10))

        mask = PAE_PFN_MASK if pae else PFN_MASK
        # x64: PML4 0-255 -> PDPT of 512 entries. PAE: there is no PML4; PDPT entries 0-1 (user 2GB) are the top level.
        for i4 in ([0] if pae else range(256)):
            if pae:
                e4, pdpt, n3 = 1, pml4, 2
            else:
                e4, = struct.unpack_from("<Q", pml4, i4 * 8)
                if not usable(e4):
                    continue
                try:
                    pdpt = phys.read(e4 & PFN_MASK, 0x1000)
                except exceptions.InvalidAddressException:
                    continue
                n3 = 512
            for i3 in range(n3):
                e3, = struct.unpack_from("<Q", pdpt, i3 * 8)
                if pae and not e3 & 1:
                    continue
                if not usable(e3) or (not pae and e3 & 1 and e3 & 0x80):
                    continue
                try:
                    pd = phys.read(e3 & mask, 0x1000)
                except exceptions.InvalidAddressException:
                    continue
                for i2 in range(512):
                    e2, = struct.unpack_from("<Q", pd, i2 * 8)
                    if not usable(e2) or (e2 & 1 and e2 & 0x80):
                        continue
                    try:
                        pt = phys.read(e2 & mask, 0x1000)
                    except exceptions.InvalidAddressException:
                        continue
                    walked["page_tables" if e4 & e3 & e2 & 1 else "page_tables_via_transition"] += 1
                    for i1 in range(512):
                        e1, = struct.unpack_from("<Q", pt, i1 * 8)
                        if e1 == 0 or e1 & 1 or e1 & (1 << 10) or e1 & (1 << 11):
                            continue
                        va = (i4 << 39) | (i3 << 30) | (i2 << 21) | (i1 << 12)
                        if (e4 | e3 | e2) & 1 and e4 & e3 & e2 & 1:
                            entries.append((pid, va, e1))
                        else:
                            walked["ptes_under_transition_upper_level_skipped"] += 1

    def decode(e, how):
        high = e >> 32
        swizzle = (e >> swz_bit) & 1
        if how == "M":
            high = high & ~mask_hi if not swizzle else high
        elif how == "F":
            high &= ~mask_hi
        elif how == "X":
            high ^= mask_hi
        number = (e >> 1) & 0xF if how == "V" else (e >> low_shift) & 0xF
        return number, high

    def in_vad(pid, va):
        rs = vads.get(pid, [])
        lo, hi = 0, len(rs)
        while lo < hi:
            mid = (lo + hi) // 2
            if rs[mid][0] <= va:
                lo = mid + 1
            else:
                hi = mid
        return lo > 0 and rs[lo - 1][0] <= va <= rs[lo - 1][1]

    subsets = {"all": entries, "in_vad": [x for x in entries if in_vad(x[0], x[1])]}
    report_sets = {name: judge(sub, decode, paging, allocated, swz_bit, low_shift, mask_hi) for name, sub in subsets.items()}

    dump = out.with_suffix(".entries.json")          # raw data for later recounts (not meant for version control)
    bitmaps = {str(k): (v["_raw"].hex() if v["_raw"] else None) for k, v in paging.items()}
    dump.write_text(json.dumps({"entries": entries, "vads": vads, "bitmaps": bitmaps}), encoding="utf-8")
    for p in paging.values():
        p.pop("_raw")
    report = {
        "image": str(mem),
        "invalid_pte_mask": hex(invalid_pte_mask),
        "mmpte_software": {k: {"start": v[0], "length": v[1]} for k, v in layout.items()},
        "paging_files": {str(k): v for k, v in paging.items()},
        "walk": dict(walked),
        "sets": report_sets,
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps({"walk": report["walk"], "sets": {k: {kk: v[kk] for kk in ("software_ptes", "decodings", "swizzle1_with_mask_bit")} for k, v in report_sets.items()}}, indent=1))


def judge(entries, decode, paging, allocated, swz_bit, low_shift, mask_hi):
    kinds = Counter()
    by_swizzle = Counter()
    protections = Counter()
    for _, _, e in entries:
        swizzle = (e >> swz_bit) & 1
        high = e >> 32
        number = (e >> low_shift) & 0xF
        m_number, m_high = decode(e, "M")
        if high == LOOKUP_NEEDED:
            kinds[f"high_ffffffff_swizzle{swizzle}"] += 1
        elif m_high == 0 and m_number == 0:
            kinds[f"demand_zero_swizzle{swizzle}"] += 1
        else:
            kinds[f"pagefile{number}_swizzle{swizzle}"] += 1
        by_swizzle[(swizzle, bool(high & mask_hi))] += 1
        if m_high not in (0, LOOKUP_NEEDED):
            protections[((e >> 5) & 0x1F, bool(e & 0x80))] += 1

    results = {}
    for how in ("M", "F", "X", "V"):
        stat = Counter()
        slots = defaultdict(list)
        for pid, va, e in entries:
            if (e >> 32) == LOOKUP_NEEDED:
                continue
            number, high = decode(e, how)
            if high == 0:
                stat["offset_zero"] += 1
                continue
            stat["decoded"] += 1
            p = paging.get(number)
            if p is None:
                stat["no_such_paging_file"] += 1
                continue
            if high >= p["size_pages"]:
                stat["beyond_file_size"] += 1
            a = allocated(number, high)
            stat[{True: "bitmap_set", False: "bitmap_clear", None: "bitmap_unknown"}[a]] += 1
            slots[(number, high)].append((pid, va))
        shared = [k for k, v in slots.items() if len(v) > 1]
        stat["distinct_slots"] = len(slots)
        stat["slots_used_by_more_than_one_pte"] = len(shared)
        stat["ptes_on_shared_slots"] = sum(len(slots[k]) for k in shared)
        results[how] = dict(stat)

    # SwizzleBit 1 side only: the cases where M (keep) and F (clear) differ
    split = Counter()
    for pid, va, e in entries:
        high = e >> 32
        swizzle = (e >> swz_bit) & 1
        number = (e >> low_shift) & 0xF
        if not swizzle or high == LOOKUP_NEEDED or not (high & mask_hi):
            continue
        for how, h in (("keep", high), ("clear", high & ~mask_hi)):
            if h >= paging.get(number, {}).get("size_pages", 0):
                split[f"{how}_beyond_size_pf{number}"] += 1
            a = allocated(number, h)
            if number in paging:
                split[f"pf{number}_{how}_{ {True: 'set', False: 'clear', None: 'unknown'}[a] }"] += 1
            else:
                split[f"pf_missing_{how}"] += 1
    return {
        "software_ptes": len(entries),
        "kinds": dict(kinds),
        "swizzle_vs_mask_bit": {f"swizzle{s}_maskbit{int(b)}": n for (s, b), n in by_swizzle.items()},
        "protection_of_pagefile_ptes": {f"prot{p}_bit7_{int(b)}": n for (p, b), n in sorted(protections.items())},
        "decodings": results,
        "swizzle1_with_mask_bit": dict(sorted(split.items())),
    }


if __name__ == "__main__":
    main()
