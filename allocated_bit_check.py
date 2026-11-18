"""Check in three ways whether the slot that a page file PTE with PageFileAllocated 0 points to is that page's slot.

Started from a tester's follow-up question on PR #2080 (issuecomment-6916761593: PTEs with protection 0x10 MM_DECOMMIT that still have a page file number).
Volatility's and MemProcFS's decoding are not used. Only pte_swizzle_probe.py raw data (.entries.json) and marker_check.py raw data (.raw.json.gz) are used.

  1. Kernel allocation bitmap: is the slot in use
  2. Same slot: does another PTE also point to the same (page file, slot) (two private pages cannot share one slot)
  3. Markers (VM only): the markers that pressure.ps1 in the test VM wrote in every page. If a page read from the page file has a marker pair,
     check whether the page of a PageFileAllocated 1 PTE that points to the same slot has the same marker as its own (then the slot's owner is that page).

Only PTEs inside VADs, in pagefile.sys (number 0), with PageFileHigh not 0 and not all ones, and inside the file size are counted. Slots are decoded with rule M.
Usage: allocated_bit_check.py <output json> <name>=<probe .entries.json>[,<marker .raw.json.gz>] [...]
"""
import bisect
import gzip
import json
import sys
from collections import Counter, defaultdict

LOOKUP_NEEDED = 0xFFFFFFFF


def check(entries_path, marker_path=None):
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    dump = json.load(open(entries_path, encoding="utf-8"))
    sw = probe["mmpte_software"]
    if "PageFileAllocated" not in sw:
        return {"entries": entries_path, "skipped": "_MMPTE_SOFTWARE has no PageFileAllocated"}
    low, alloc = sw["PageFileLow"]["start"], sw["PageFileAllocated"]["start"]
    res = sw["PageFileReserved"]["start"] if "PageFileReserved" in sw else None
    swz = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    # For images whose page file list could not be read, the size and bitmap checks stay empty
    size = probe["paging_files"].get("0", {}).get("size_pages", 1 << 32)
    raw_bm = dump["bitmaps"].get("0")
    bm = bytes.fromhex(raw_bm) if raw_bm else None
    vads = {int(k): sorted(v) for k, v in dump["vads"].items()}
    starts = {p: [a for a, _ in v] for p, v in vads.items()}

    def in_vad(pid, va):
        i = bisect.bisect_right(starts.get(pid, []), va) - 1
        return i >= 0 and vads[pid][i][0] <= va <= vads[pid][i][1]

    ptes = {}                                     # (pid, vpn) -> (slot, A, R, prot)
    by_slot = defaultdict(list)
    for pid, va, e in dump["entries"]:
        high = e >> 32
        if high == LOOKUP_NEEDED or (e >> low) & 0xF or not in_vad(pid, va):
            continue
        slot = high if (swz is not None and (e >> swz) & 1) else high & ~mask_hi & 0xFFFFFFFF
        if slot == 0 or slot >= size:
            continue
        a, r = (e >> alloc) & 1, ((e >> res) & 1 if res is not None else None)
        ptes[(pid, va >> 12)] = (slot, a, r, (e >> 5) & 0x1F)
        by_slot[slot].append((pid, va >> 12, a))

    # PTEs per slot, and how many of them have PageFileAllocated set (counted
    # once, so that slots named by many PTEs don't make this quadratic)
    on_slot = Counter(slot for slot, _, _, _ in ptes.values())
    a1_on_slot = Counter(slot for slot, a, _, _ in ptes.values() if a == 1)
    stat = defaultdict(Counter)
    for (pid, vpn), (slot, a, r, prot) in ptes.items():
        s = stat[f"allocated_{a}"]
        s["ptes"] += 1
        if bm is not None and slot >> 3 < len(bm):
            s["bitmap_set" if bm[slot >> 3] & (1 << (slot & 7)) else "bitmap_clear"] += 1
        if on_slot[slot] > 1:
            s["slot_also_in_another_pte"] += 1
            if a1_on_slot[slot] - a > 0:
                s["slot_also_in_a_pte_with_allocated_1"] += 1
        s[f"protection_{prot:#04x}"] += 1
        if r is not None:
            s[f"reserved_{r}"] += 1
    result = {"entries": entries_path, "page_file_allocated_bit": alloc, "page_file_reserved_bit": res,
              "by_allocated": {k: dict(sorted(v.items())) for k, v in sorted(stat.items())}}

    if marker_path:
        m = json.load(gzip.open(marker_path, "rt", encoding="utf-8"))
        marks = {(r[0], r[-1]): tuple(r[2:-1]) for r in m["records"]}
        sources = {(r[0], r[-1]): r[1] for r in m["records"]}
        mk = Counter()
        for r in m["records"]:
            pid, src, vpn = r[0], r[1], r[-1]
            if src.startswith("swap") and (pid, vpn) in ptes:
                mk[f"read_from_page_file__marker_pair__allocated_{ptes[(pid, vpn)][1]}"] += 1
        for r in m["others"]:
            pid, src, kind, vpn = r[0], r[1], r[2], r[3]
            if src.startswith("swap") and (pid, vpn) in ptes:
                mk[f"read_from_page_file__{kind}__allocated_{ptes[(pid, vpn)][1]}"] += 1
        for (pid, vpn), key in marks.items():
            p = ptes.get((pid, vpn))
            if p is None or p[1] == 1 or not sources[(pid, vpn)].startswith("swap"):
                continue
            owners = [o for o in by_slot[p[0]] if (o[0], o[1]) != (pid, vpn) and o[2] == 1]
            if not owners:
                mk["allocated_0_marker_pair__no_other_pte_on_slot"] += 1
            elif any(marks.get((o[0], o[1])) == key for o in owners):
                mk["allocated_0_marker_pair__an_allocated_1_pte_on_the_slot_has_this_marker"] += 1
            elif all((o[0], o[1]) not in marks for o in owners):
                # the slot owner's page is outside the marker check range (large private VADs of powershell), so markers cannot be compared
                mk["allocated_0_marker_pair__allocated_1_pte_on_slot_not_marker_checked"] += 1
            else:
                mk["allocated_0_marker_pair__allocated_1_pte_on_slot_with_other_marker"] += 1
        result["markers"] = dict(sorted(mk.items()))
    return result


def main():
    out = sys.argv[1]
    report = {}
    for arg in sys.argv[2:]:
        name, paths = arg.split("=", 1)
        entries, _, marker = paths.partition(",")
        report[name] = check(entries, marker or None)
        print(name, json.dumps({k: v for k, v in report[name].items() if k != "entries"}))
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=1)


if __name__ == "__main__":
    main()
