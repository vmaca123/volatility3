"""Check that the bytes are right when a paged-out page is read from the middle of the page (written to check the third commit of PR #2080).

From pte_swizzle_probe.py raw data, pick random pagefile.sys (number 0) PTEs inside VADs, and read the Volatility layer
at a random offset and length inside the page. There are two references:
- Direct: the bytes read straight from pagefile.sys at (slot decoded by the rule used here << 12) + offset in page (only reads that end inside the page)
- MemProcFS: the bytes MemProcFS reads at the same process, address and length (compared later by mpfs_read_compare.py)
Reads that cross a page boundary are mixed in too (for those, only the MemProcFS reference applies).

Usage: PYTHONPATH=<vol3 checkout> python subpage_read_check.py <memory.mem> <pagefile.sys> <probe .entries.json> <output json> [sample size]
"""
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

import volatility3
import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, exceptions, plugins
from volatility3.plugins.windows import pslist

PAGE = 0x1000


def main():
    mem, swap, entries_path, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3], Path(sys.argv[4])
    want = int(sys.argv[5]) if len(sys.argv) > 5 else 600
    probe = json.load(open(entries_path.replace(".entries.json", ".json"), encoding="utf-8"))
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    size_pages = probe["paging_files"]["0"]["size_pages"]
    dump = json.load(open(entries_path, encoding="utf-8"))
    vads = {int(k): v for k, v in dump["vads"].items()}

    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = mem.as_uri()
    ctx.config["automagic.WinSwapLayers.single_swap_locations"] = [swap.as_uri()]
    ams = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    plug = plugins.construct_plugin(ctx, ams, pslist.PsList, "plugins.PsList", None, None)
    procs = {}
    for proc in pslist.PsList.list_processes(ctx, plug.config["kernel"]):
        try:
            procs[int(proc.UniqueProcessId)] = ctx.layers[proc.add_process_layer()]
        except exceptions.InvalidAddressException:
            pass

    def in_vad(pid, va):
        return any(lo <= va <= hi for lo, hi in vads.get(pid, []))

    candidates = []
    for pid, va, pte in dump["entries"]:
        high = pte >> 32
        swz = (pte >> 4) & 1
        slot = (high & ~mask_hi & 0xFFFFFFFF) if swz == 0 else high
        if (pid in procs and ((pte >> 12) & 0xF) == 0 and (pte >> 5) & 0x1F and 0 < slot < size_pages
                and high != 0xFFFFFFFF and in_vad(pid, va)):
            candidates.append((pid, va, slot))
    rng = random.Random(20261108)
    sample = rng.sample(candidates, min(want, len(candidates)))
    pf = open(swap, "rb")
    rows, totals = [], Counter()
    for i, (pid, va, slot) in enumerate(sample):
        crossing = i % 4 == 3
        if crossing:
            offset = rng.randrange(PAGE - 64, PAGE)
            length = rng.randrange(PAGE - offset + 1, PAGE - offset + 128)
        else:
            offset = rng.randrange(1, PAGE)
            length = rng.randrange(1, min(512, PAGE - offset) + 1)
        try:
            data = procs[pid].read(va + offset, length)
        except exceptions.InvalidAddressException:
            totals["volatility_unreadable"] += 1
            continue
        direct = None
        if not crossing:
            pf.seek(slot * PAGE + offset)
            direct = pf.read(length)
            totals["inside_same_as_direct" if data == direct else "inside_differs_from_direct"] += 1
            pf.seek(slot * PAGE)
            slot_start = pf.read(length)
            if data == slot_start and data != direct:
                totals["inside_equals_slot_start_instead"] += 1
        else:
            totals["crossing_read"] += 1
        rows.append([pid, va + offset, length, hashlib.sha256(data).hexdigest(), crossing])
    report = {
        "volatility3": volatility3.__file__,
        "candidates": len(candidates),
        "sample": len(sample),
        "totals": dict(totals),
        "reads": rows,
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in report.items() if k != "reads"}, indent=1))


if __name__ == "__main__":
    main()
