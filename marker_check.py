"""Use the markers that pressure.ps1 in the test VM wrote in every page to judge directly whether the page content Volatility read is right.

pressure.ps1 writes "LABPAGE|<Id>|<block>|<page>|<offset>|" at array offsets 0 and 2048 of every 4KB of a 64MB byte array.
The data of a .NET array starts after the object header, so the markers are not at the very start of the virtual page,
but at the same place d, d+2048 inside every page.

Reads the large (32MB or more) private VADs of powershell.exe processes, one whole 4KB page at a time, and checks
- where the page was read from (physical memory / pagefile / another page file number (compressed store etc.) / unreadable),
- whether the page has exactly two markers, 2048 apart, with offset fields 0 and 2048, and the same Id, block and page (pair_ok),
- whether the page number matches the address: within the same (Id, block), whether (virtual page number - marker page number) equals the most common value.
If both hold: good; if the marker pair is fine but the place is different: misplaced (the content of another page was read); if the pair is not fine: bad.
Pages without markers (outside the array, .NET header etc.) are counted separately as zero / no_marker.

Note: in a first run, the bad and misplaced examples were heap pages full of the small temporary byte arrays that PowerShell creates
while building the markers (a length field of 0x13-0x17 plus one marker). So every page is split into "inside an array (in_array)" and "outside (outside)".
Inside an array = a page in the virtual page range [base, base+16383] of some 64MB array in the same process. A page inside an array must show
that array's marker with its own page number, so anything inside an array that is not good (misplaced, bad, no_marker, zero) is a page that was really read wrong.
bad and misplaced outside arrays are heap garbage and are not used for the verdict.
Usage: PYTHONPATH=<vol3 checkout> python marker_check.py <memory image> <output json> [pagefile.sys ...]
"""
import bisect
import gzip
import json
import re
import sys
from array import array
from collections import Counter
from pathlib import Path

import volatility3
import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, exceptions, plugins
from volatility3.plugins.windows import pslist

PAGE = 0x1000
MARK = re.compile(rb"LABPAGE\|(\d+)\|(\d+)\|(\d+)\|(\d+)\|")
MIN_VOTES = 256           # minimum number of votes to accept a place as an array (of 16,384 pages)


def look(data):
    """Find markers in a 4KB page. Returns (kind, key, offset of the first marker). kind = pair / bad / zero / no_marker."""
    marks = [(m.start(), m.groups()) for m in MARK.finditer(data)]
    if not marks:
        return ("zero" if not any(data) else "no_marker"), None, None
    if len(marks) == 2:
        (o0, g0), (o1, g1) = marks
        if o1 - o0 == 2048 and g0[3] == b"0" and g1[3] == b"2048" and g0[:3] == g1[:3]:
            return "pair", tuple(int(x) for x in g0[:3]), o0
    return "bad", None, marks[0][0]


def source(layer, va):
    """Where the page is read from: memory / swap_layersN / swapped_pfN / paged / invalid."""
    try:
        _, _, name = layer._translate(va)
        return "memory" if not name.startswith("swap") else name.split(".")[-1]
    except exceptions.SwappedInvalidAddressException as e:
        n = (e.entry >> layer.config.get("page_file_low_bit", 1)) & 0xF if layer.config.get("page_file_low_bit") is not None else "?"
        return f"swapped_pf{n}"
    except exceptions.PagedInvalidAddressException:
        return "paged"
    except exceptions.InvalidAddressException:
        return "invalid"


def main():
    mem, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    swaps = [Path(p).resolve().as_uri() for p in sys.argv[3:]]
    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = mem.as_uri()
    if swaps:
        ctx.config["automagic.WinSwapLayers.single_swap_locations"] = swaps
    ams = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    plug = plugins.construct_plugin(ctx, ams, pslist.PsList, "plugins.PsList", None, None)
    kernel_layer = ctx.layers[ctx.modules[plug.config["kernel"]].layer_name]
    settings = {k: kernel_layer.config.get(k) for k in ("page_file_low_bit", "swizzle_bit", "invalid_pte_mask")}

    per_source = Counter()
    examples = {}
    records = []          # (pid, source, (Id, block, page), virtual page number) - only pages with a matching pair
    others = []           # (pid, source, kind, virtual page number, first 64 bytes) - pages without a pair
    unreadable = {}       # (pid, source) -> virtual page numbers that could not be read
    offsets = Counter()   # marker offset inside the page
    procs = 0
    for proc in pslist.PsList.list_processes(ctx, plug.config["kernel"]):
        name = proc.ImageFileName.cast("string", max_length=15, errors="replace").lower()
        if name != "powershell.exe":
            continue
        try:
            layer = ctx.layers[proc.add_process_layer()]
        except exceptions.InvalidAddressException:
            continue
        procs += 1
        for vad in proc.get_vad_root().traverse():
            try:
                start, end = vad.get_start(), vad.get_end()
                private = vad.get_private_memory()
            except (exceptions.InvalidAddressException, AttributeError):
                continue
            if not private or end - start + 1 < 32 * 1024 * 1024:
                continue
            pid = int(proc.UniqueProcessId)
            for va in range(start, end + 1, PAGE):
                src = source(layer, va)
                try:
                    data = layer.read(va, PAGE)
                except exceptions.InvalidAddressException:
                    unreadable.setdefault((pid, src), array("Q")).append(va >> 12)
                    continue
                kind, key, off = look(data)
                if kind == "pair":
                    records.append((pid, src, key, va >> 12))
                    offsets[off] += 1
                    continue
                others.append((pid, src, kind, va >> 12, data[:64].hex() if kind != "zero" else ""))
    # For each (Id, block), the most common (virtual page number - marker page number) is taken as that array's base.
    # Inside that array's virtual page range [base, base+16383], the array's markers must appear with that page number.
    # Raw data is kept so results can be recounted without reading the dump again. Unreadable pages are reduced to contiguous runs.
    raw = {"records": [[pid, src, *key, vpn] for pid, src, key, vpn in records],
           "others": [[pid, src, kind, vpn] for pid, src, kind, vpn, _ in others],
           "unreadable": {}}
    for (pid, src), vpns in unreadable.items():
        runs, s0, prev = [], None, None
        for v in vpns:
            if s0 is None:
                s0 = prev = v
            elif v == prev + 1:
                prev = v
            else:
                runs.append([s0, prev]); s0 = prev = v
        if s0 is not None:
            runs.append([s0, prev])
        raw["unreadable"][f"{pid}|{src}"] = runs
    with gzip.open(str(out) + ".raw.json.gz", "wt", encoding="utf-8") as fh:
        json.dump(raw, fh)

    base_votes = {}
    for pid, _, key, vpn in records:
        base_votes.setdefault(key[:2], Counter())[(pid, vpn - key[2])] += 1
    # For arrays that barely appear in a dump, the votes of a few heap garbage pages (temporary marker arrays) made a wrong
    # place into an "array". Only places with at least MIN_VOTES votes are treated as arrays.
    base = {k: c.most_common(1)[0][0] for k, c in base_votes.items() if c.most_common(1)[0][1] >= MIN_VOTES}
    rejected = {f"{k[0]}|{k[1]}": c.most_common(1)[0][1] for k, c in base_votes.items() if c.most_common(1)[0][1] < MIN_VOTES}
    ranges = {}
    for (pid, b) in base.values():
        ranges.setdefault(pid, []).append(b)
    for pid in ranges:
        ranges[pid].sort()
    pages_per_array = 64 * 1024 * 1024 // PAGE

    def where(pid, vpn):
        starts = ranges.get(pid, [])
        i = bisect.bisect_right(starts, vpn) - 1
        return "in_array" if i >= 0 and vpn - starts[i] < pages_per_array else "outside"

    totals = Counter()
    for pid, src, key, vpn in records:
        good = base.get(key[:2]) == (pid, vpn - key[2])
        place = where(pid, vpn)
        verdict = "good" if good else "misplaced"
        per_source[(src, place, verdict)] += 1
        totals[(place, verdict)] += 1
        if not good and (src, place) not in examples:
            b = base.get(key[:2])
            examples[(src, place)] = {"pid": pid, "vpn": hex(vpn), "key": key,
                                      "expected": [b[0], hex(b[1] + key[2])] if b else "array not seen"}
    for pid, src, kind, vpn, head in others:
        place = where(pid, vpn)
        per_source[(src, place, kind)] += 1
        totals[(place, kind)] += 1
        if place == "in_array" and (src, place, kind) not in examples:
            examples[(src, place, kind)] = {"pid": pid, "vpn": hex(vpn), "head64": head}
    for (pid, src), vpns in unreadable.items():
        for vpn in vpns:
            place = where(pid, vpn)
            per_source[(src, place, "unreadable")] += 1
            totals[(place, "unreadable")] += 1
    report = {
        "volatility3": volatility3.__file__,
        "image": str(mem),
        "swap_files": swaps,
        "layer_settings": settings,
        "powershell_processes": procs,
        "arrays_seen": len(base),
        "min_votes": MIN_VOTES,
        "arrays_rejected_few_votes": rejected,
        "pages_per_array": pages_per_array,
        "marker_offsets_in_page": {str(k): v for k, v in offsets.most_common(8)},
        "totals": {f"{p}:{k}": n for (p, k), n in sorted(totals.items())},
        "by_source": {f"{s}:{p}:{k}": n for (s, p, k), n in sorted(per_source.items())},
        "examples": {":".join(map(str, k)): v for k, v in examples.items()},
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("examples", "by_source")}, indent=1))


if __name__ == "__main__":
    main()
