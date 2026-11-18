"""Reads pages whose PTE has PageFileAllocated clear with MemProcFS, and checks whether the slot owner's marker (another page's content) comes back.

Volatility read the slots of such PTEs and returned another page's content; this checks whether MemProcFS reads the same slot.

Input: the raw marker data (marker_check.py's .raw.json.gz) and pte_swizzle_probe.py's raw output (.entries.json).
Picks the pages that a branch without the PageFileAllocated check read from the page file with a marker pair,
and whose PTE has PageFileAllocated clear. Reads the same (process, address) with MemProcFS one page at a time
(FLAG_NOCACHE), looks for markers, and counts whether the marker equals the one Volatility read and whether a PTE
with the bit set on the same slot owns that marker.
Usage (MemProcFS environment): mpfs_allocated0_markers.py <memory> <pagefile.sys> <probe .entries.json> <marker .raw.json.gz> <out json>
"""
import gzip
import json
import re
import sys
from collections import Counter, defaultdict

import memprocfs

MARK = re.compile(rb"LABPAGE\|(\d+)\|(\d+)\|(\d+)\|(\d+)\|")


def main():
    mem, pagefile, entries_path, marker_path, out = sys.argv[1:6]
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    sw = probe["mmpte_software"]
    low, alloc = sw["PageFileLow"]["start"], sw["PageFileAllocated"]["start"]
    swz = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    entries = json.load(open(entries_path, encoding="utf-8"))["entries"]
    pte = {}
    by_slot = defaultdict(list)
    for pid, va, e in entries:
        high = e >> 32
        if high in (0, 0xFFFFFFFF) or (e >> low) & 0xF:
            continue
        slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
        pte[(pid, va >> 12)] = (slot, (e >> alloc) & 1)
        by_slot[slot].append((pid, va >> 12, (e >> alloc) & 1))
    m = json.load(gzip.open(marker_path, "rt", encoding="utf-8"))
    marks = {(r[0], r[-1]): tuple(r[2:-1]) for r in m["records"]}
    source = {(r[0], r[-1]): r[1] for r in m["records"]}
    picked = [(pid, vpn, key) for (pid, vpn), key in marks.items()
              if (pid, vpn) in pte and pte[(pid, vpn)][1] == 0 and source[(pid, vpn)].startswith("swap")]
    vmm = memprocfs.Vmm(["-device", mem, "-pagefile0", pagefile])
    totals, rows = Counter(), []
    for pid, vpn, key in picked:
        try:
            data = vmm.process(pid).memory.read(vpn << 12, 0x1000, memprocfs.FLAG_NOCACHE)
        except Exception:
            data = None
        slot = pte[(pid, vpn)][0]
        owners = [o for o in by_slot[slot] if o[2] == 1 and (o[0], o[1]) != (pid, vpn)]
        owner_has_key = any(marks.get((o[0], o[1])) == key for o in owners)
        if data is None or len(data) != 0x1000:
            kind = "memprocfs_unreadable"
        elif not any(data):
            kind = "memprocfs_zero"
        else:
            found = [tuple(int(x) for x in g.groups()[:3]) for g in MARK.finditer(data)]
            kind = "memprocfs_same_marker_as_volatility" if key in found else (
                "memprocfs_other_marker" if found else "memprocfs_no_marker")
        totals[kind] += 1
        totals[f"{kind}__slot_owner_with_bit_set_shows_this_marker_{owner_has_key}"] += 1
        rows.append({"pid": pid, "va": hex(vpn << 12), "slot": slot, "marker": key, "result": kind,
                     "owner_with_bit_set_shows_this_marker": owner_has_key})
    report = {"image": mem, "pages": len(picked), "totals": dict(sorted(totals.items())), "rows": rows}
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=1))


if __name__ == "__main__":
    main()
