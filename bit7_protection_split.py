"""Splits page file PTEs by protection value and checks their slots against the kernel's allocation bitmap.

Written for a tester's follow-up question on PR #2080 (issuecomment-6916761593): whether the slots named by PTEs with
bit 7 clear (which develop did not read) are in use in _MMPAGING_FILE.Bitmaps->AllocationBitmap, and how protection
0x10 (MM_DECOMMIT) and 0x18 (MM_NOACCESS) compare. Uses only pte_swizzle_probe.py's raw output (.entries.json: PTE values,
VAD ranges, bitmap bytes). Uses neither Volatility nor MemProcFS.

Slots are decoded with rule M of pte_swizzle_probe.py (when SwizzleBit is 0, the upper 32 bits of the mask are removed).
Only PTEs inside a VAD are counted. PageFileHigh 0 (demand zero) and all ones (VAD lookup) are left out.

Usage: bit7_protection_split.py <out json> <name>=<probe .entries.json> [...]
"""
import bisect
import json
import sys
from collections import Counter, defaultdict

LOOKUP_NEEDED = 0xFFFFFFFF
NAMES = {0x10: "MM_DECOMMIT", 0x18: "MM_NOACCESS"}


def split(entries_path):
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    dump = json.load(open(entries_path, encoding="utf-8"))
    sw = probe["mmpte_software"]
    low = sw["PageFileLow"]["start"]
    swz_bit = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    flags = {n: sw[n]["start"] for n in ("PageFileReserved", "PageFileAllocated") if n in sw}
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    sizes = {int(k): v["size_pages"] for k, v in probe["paging_files"].items()}
    virtual = {int(k) for k, v in probe["paging_files"].items() if v["virtual_store"]}
    bitmaps = {int(k): (bytes.fromhex(v) if v else None) for k, v in dump["bitmaps"].items()}
    vads = {int(k): sorted(v) for k, v in dump["vads"].items()}

    starts = {pid: [lo for lo, _ in rs] for pid, rs in vads.items()}

    def vad_of(pid, va):
        i = bisect.bisect_right(starts.get(pid, []), va) - 1
        if i >= 0 and vads[pid][i][0] <= va <= vads[pid][i][1]:
            return tuple(vads[pid][i])
        return None

    groups = defaultdict(Counter)
    where = defaultdict(lambda: defaultdict(set))
    slots = defaultdict(list)
    for pid, va, e in dump["entries"]:
        high = e >> 32
        if high == LOOKUP_NEEDED:
            continue
        vad = vad_of(pid, va)
        if vad is None:
            continue
        swizzle = (e >> swz_bit) & 1 if swz_bit is not None else 0
        slot = high if swizzle else high & ~mask_hi & 0xFFFFFFFF
        number = (e >> low) & 0xF
        if slot == 0:
            continue
        prot = (e >> 5) & 0x1F
        key = f"prot_{prot:#04x}_bit7_{(e >> 7) & 1}"
        g = groups[key]
        g["ptes"] += 1
        g[f"page_file_{number}" + ("_virtual_store" if number in virtual else "")] += 1
        raw = bitmaps.get(number)
        if number not in sizes:
            g["no_such_paging_file"] += 1
        elif slot >= sizes[number]:
            g["beyond_file_size"] += 1
        if raw is None or slot >> 3 >= len(raw):
            g["bitmap_unknown"] += 1
        else:
            g["bitmap_set" if raw[slot >> 3] & (1 << (slot & 7)) else "bitmap_clear"] += 1
        for name, bit in flags.items():
            g[f"{name}_{(e >> bit) & 1}"] += 1
        where[key]["processes"].add(pid)
        where[key]["vads"].add((pid, vad))
        slots[(number, slot)].append(key)
    for key, owners in ((k, v) for s, v in slots.items() if len(v) > 1 for k in v):
        groups[key]["on_a_slot_shared_with_another_pte"] += 1
    out = {}
    for key in sorted(groups):
        g = dict(sorted(groups[key].items()))
        g["processes"] = len(where[key]["processes"])
        g["vads"] = len(where[key]["vads"])
        prot = int(key.split("_")[1], 16)
        if prot in NAMES:
            g["wrk_name"] = NAMES[prot]
        out[key] = g
    totals = Counter()
    for key, g in out.items():
        side = "bit7_clear" if key.endswith("bit7_0") else "bit7_set"
        for k in ("ptes", "bitmap_set", "bitmap_clear", "bitmap_unknown"):
            totals[f"{side}_{k}"] += g.get(k, 0)
    return {"entries": entries_path, "invalid_pte_mask": probe["invalid_pte_mask"], "page_file_low_bit": low,
            "swizzle_bit": swz_bit, "totals": dict(sorted(totals.items())), "by_protection": out}


def main():
    out = sys.argv[1]
    report = {}
    for arg in sys.argv[2:]:
        name, path = arg.split("=", 1)
        report[name] = split(path)
        print(name, json.dumps(report[name]["totals"]))
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=1)


if __name__ == "__main__":
    main()
