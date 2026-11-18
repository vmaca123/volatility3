"""Splits the pages in mpfs_allocated0_markers.py output by the state of their page file slot (2026-11-19).

For each page (PageFileAllocated clear, a marker pair read from the page file) it counts:
- whether the slot is in use or free in AllocationBitmap,
- whether another walked PTE with PageFileAllocated set names the same slot, and whether that PTE is in another process,
- whether that PTE's page sits at the marker's array position (the marker check read the same marker from that PTE's page).
It uses neither Volatility nor MemProcFS.
Run: python mpfs_marker_slot_state.py <out.json> <name>=<mpfs_allocated0_markers out.json>,<probe .entries.json> [...]
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def main():
    out = sys.argv[1]
    report = {}
    for arg in sys.argv[2:]:
        name, paths = arg.split("=", 1)
        mpfs_path, entries_path = paths.split(",")
        rows = json.load(open(mpfs_path, encoding="utf-8"))["rows"]
        probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
        dump = json.load(open(entries_path, encoding="utf-8"))
        sw = probe["mmpte_software"]
        low, alloc = sw["PageFileLow"]["start"], sw["PageFileAllocated"]["start"]
        swz = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
        mask = probe["invalid_pte_mask"]
        mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
        bm = bytes.fromhex(dump["bitmaps"]["0"])
        bit_set_on_slot = defaultdict(list)
        for pid, va, e in dump["entries"]:
            high = e >> 32
            if high in (0, 0xFFFFFFFF) or (e >> low) & 0xF or not (e >> alloc) & 1:
                continue
            slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
            bit_set_on_slot[slot].append(pid)
        c = Counter()
        for r in rows:
            s = r["slot"]
            owners = bit_set_on_slot.get(s, [])
            c["pages"] += 1
            c["memprocfs_" + r["result"].removeprefix("memprocfs_")] += 1
            c["slot_free_in_allocation_bitmap" if not bm[s >> 3] & (1 << (s & 7)) else "slot_used_in_allocation_bitmap"] += 1
            if owners:
                c["slot_also_named_by_pte_with_bit_set"] += 1
                c["slot_also_named_by_pte_with_bit_set_in_other_process"] += any(p != r["pid"] for p in owners)
            c["bit_set_pte_on_slot_is_at_marker_position"] += bool(r["owner_with_bit_set_shows_this_marker"])
        report[name] = dict(sorted(c.items()))
    Path(out).write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
