"""Compares two marker check runs (before commit 5, and commit 5) page by page (2026-11-19, re-run of the VM checks for PR #2080 commit 5).

Takes two marker_check.py raw outputs (.raw.json.gz) and the pte_swizzle_probe.py raw output (.entries.json).
For every page that the earlier run read from a page file (any swap layer), it records where the commit 5 run read it from
(same source / unreadable / other source), split by what the earlier run found on the page (marker pair, bad, no_marker,
zero) and the PageFileAllocated bit of the page's PTE.
It also counts the other direction (pages that the commit 5 run reads from the page file but the earlier run did not).
It uses neither Volatility nor MemProcFS.
Run: python marker_commit5_diff.py <earlier .raw.json.gz> <commit 5 .raw.json.gz> <probe .entries.json> <out.json>
"""
import bisect
import gzip
import json
import sys
from collections import Counter
from pathlib import Path


def load(path):
    raw = json.load(gzip.open(path, "rt", encoding="utf-8"))
    pages = {}
    for r in raw["records"]:
        pages[(r[0], r[-1])] = (r[1], "marker_pair")      # pages with a full marker pair (in or outside an array; only the source matters here)
    for pid, src, kind, vpn in raw["others"]:
        pages[(pid, vpn)] = (src, kind)
    runs = {}
    for key, rs in raw["unreadable"].items():
        pid, src = key.split("|", 1)
        runs.setdefault(int(pid), []).extend((a, b, src) for a, b in rs)
    for pid in runs:
        runs[pid].sort()
    return pages, runs


def unreadable_source(runs, pid, vpn):
    rs = runs.get(pid, [])
    i = bisect.bisect_right(rs, (vpn, float("inf"), "")) - 1
    while i >= 0 and rs[i][0] <= vpn:
        if vpn <= rs[i][1]:
            return rs[i][2]
        i -= 1
    return None


def main():
    before_path, after_path, entries_path, out = sys.argv[1:5]
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    sw = probe["mmpte_software"]
    alloc = sw["PageFileAllocated"]["start"]
    pte = {(pid, va >> 12): e for pid, va, e in json.load(open(entries_path, encoding="utf-8"))["entries"]}
    before, before_runs = load(before_path)
    after, after_runs = load(after_path)

    def bit(pid, vpn):
        e = pte.get((pid, vpn))
        return "pte_not_in_walk" if e is None else f"allocated_{(e >> alloc) & 1}"

    moved = Counter()
    for (pid, vpn), (src, kind) in before.items():
        if not src.startswith("swap_layers"):
            continue
        if (pid, vpn) in after:
            now = "same_source" if after[(pid, vpn)][0] == src else "other_source:" + after[(pid, vpn)][0]
        else:
            u = unreadable_source(after_runs, pid, vpn)
            now = f"unreadable:{u}" if u else "not_seen"
        moved[f"{kind} -> {now} | {bit(pid, vpn)}"] += 1
    new_swap = Counter()
    for (pid, vpn), (src, kind) in after.items():
        if src.startswith("swap_layers") and not (before.get((pid, vpn), ("",))[0] == src):
            new_swap[f"{kind} | {bit(pid, vpn)}"] += 1
    report = {"before": before_path, "after": after_path, "page_file_allocated_bit": alloc,
              "before_page_file_pages_by_kind_after_and_bit": dict(sorted(moved.items())),
              "after_page_file_pages_not_page_file_before": dict(sorted(new_swap.items()))}
    Path(out).write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
