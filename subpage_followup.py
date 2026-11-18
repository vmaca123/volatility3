"""Draw the subpage_read_check.py sample again, exactly as before, and record things that were not recorded then.

Written to answer a tester's follow-up question on PR #2080 (issuecomment-6916761593).
Same seed (20261108), same candidate rule and same order of random calls, so the sample is the same. To confirm this, the hashes of the read bytes are compared with the earlier result (--earlier).

What is added
  - Reads inside one page: whether the bytes at the start of the slot equal the bytes at the offset, and whether the slot's 4KB is filled with a single byte value
  - Failed reads: the exception name, at which address it happened (first page / second page), and that page's PTE value, level and kind
  - Crossing reads: where the second page is (memory, a page file slot, or unreadable and why)
PTE kinds are decided from the kernel layout in the probe json (PageFileLow, SwizzleBit, InvalidPteMask, page file list). Volatility's decoding is not used.

Usage: PYTHONPATH=<vol3 checkout> python subpage_followup.py <memory> <pagefile.sys> <probe .entries.json> <output json> [--earlier <earlier result json>] [--sample N]
"""
import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

import volatility3
import volatility3.framework as framework
import volatility3.plugins
from volatility3.framework import automagic, contexts, exceptions, plugins
from volatility3.plugins.windows import pslist

PAGE = 0x1000
LEVEL = {12: "PTE", 21: "PDE", 30: "PDPTE", 39: "PML4E"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("memory")
    ap.add_argument("pagefile")
    ap.add_argument("entries")
    ap.add_argument("out")
    ap.add_argument("--earlier")
    ap.add_argument("--sample", type=int, default=600)
    a = ap.parse_args()
    mem, swap, out = Path(a.memory).resolve(), Path(a.pagefile).resolve(), Path(a.out)
    probe = json.load(open(a.entries.replace(".entries.json", ".json"), encoding="utf-8"))
    mask = probe["invalid_pte_mask"]
    mask_hi = (int(mask, 16) if isinstance(mask, str) else int(mask)) >> 32
    size_pages = probe["paging_files"]["0"]["size_pages"]
    sw = probe["mmpte_software"]
    low_shift = sw["PageFileLow"]["start"]
    swz_bit = sw["SwizzleBit"]["start"] if "SwizzleBit" in sw else None
    paging = {int(k): v for k, v in probe["paging_files"].items()}
    dump = json.load(open(a.entries, encoding="utf-8"))
    vads = {int(k): v for k, v in dump["vads"].items()}
    bitmaps = {int(k): (bytes.fromhex(v) if v else None) for k, v in dump["bitmaps"].items()}

    def allocated(number, slot):
        raw = bitmaps.get(number)
        if raw is None or slot >> 3 >= len(raw):
            return None
        return bool(raw[slot >> 3] & (1 << (slot & 7)))

    def kind_of_pte(e):
        """Kind of one PTE-level entry (decided directly from the kernel layout)"""
        if e == 0:
            return "pte_zero", {}
        if e & 1:
            return "valid", {}
        if e & (1 << 10):
            return "prototype", {}
        if e & (1 << 11):
            return "transition", {}
        prot = (e >> 5) & 0x1F
        high = e >> 32
        if high == 0xFFFFFFFF:
            return "vad_lookup_all_ones", {"protection": prot}
        swizzle = (e >> swz_bit) & 1 if swz_bit is not None else 0
        slot = high if swizzle else high & ~mask_hi & 0xFFFFFFFF
        number = (e >> low_shift) & 0xF
        info = {"protection": prot, "page_file": number, "slot": slot}
        if prot == 0:
            return "protection_0", info
        if slot == 0 and number == 0:
            return "demand_zero", info
        p = paging.get(number)
        if p is None:
            return "no_such_paging_file", info
        info["bitmap"] = allocated(number, slot)
        if p["virtual_store"]:
            return "compressed_store", info
        if slot >= p["size_pages"]:
            return f"pf{number}_beyond_end", info
        return f"pf{number}_slot", info

    def where(layer, va):
        """Where one page is: the Volatility layer translation result and the kind of that page's PTE"""
        page = va & ~(PAGE - 1)
        try:
            off, size, lname = layer._translate(page)
        except exceptions.PagedInvalidAddressException as excp:
            bits = excp.invalid_bits
            res = {"volatility": type(excp).__name__, "level": LEVEL.get(bits, bits), "entry": hex(excp.entry)}
            if bits == 12:
                k, info = kind_of_pte(excp.entry)
                res.update(kind=k, **info)
            else:
                res["kind"] = "upper_level_not_present"
                e = excp.entry
                res["upper_entry"] = ("zero" if e == 0 else "prototype" if e & (1 << 10) else
                                      "transition" if e & (1 << 11) else "software")
            return res
        except exceptions.InvalidAddressException as excp:
            return {"volatility": type(excp).__name__, "kind": "other_invalid"}
        res = {"layer": "swap" if "swap" in lname.lower() else "memory", "mapped": hex(off)}
        try:
            ok = layer.context.layers[lname].is_valid(off, PAGE)
        except exceptions.InvalidAddressException:
            ok = False
        if not ok:
            res["kind"] = "mapped_target_not_valid"
        else:
            res["kind"] = "readable_" + res["layer"]
        if res["layer"] == "swap":
            res["slot"] = off >> 12
        return res

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

    # The candidate rule and the order of random calls below must be exactly the same as in subpage_read_check.py (so the sample is the same)
    candidates = []
    for pid, va, pte in dump["entries"]:
        high = pte >> 32
        swz = (pte >> 4) & 1
        slot = (high & ~mask_hi & 0xFFFFFFFF) if swz == 0 else high
        if (pid in procs and ((pte >> 12) & 0xF) == 0 and (pte >> 5) & 0x1F and 0 < slot < size_pages
                and high != 0xFFFFFFFF and in_vad(pid, va)):
            candidates.append((pid, va, slot, pte))
    rng = random.Random(20261108)
    sample = rng.sample([c[:3] for c in candidates], min(a.sample, len(candidates)))
    pte_of = {(c[0], c[1]): c[3] for c in candidates}

    earlier = {}
    if a.earlier:
        for pid, va, length, h, crossing in json.load(open(a.earlier, encoding="utf-8"))["reads"]:
            earlier[(pid, va, length)] = h

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
        layer = procs[pid]
        row = {"i": i, "pid": pid, "va": hex(va), "offset": offset, "length": length, "slot": slot,
               "crossing": crossing, "pte": hex(pte_of[(pid, va)])}
        try:
            data = layer.read(va + offset, length)
            row["read"] = "ok"
            row["sha256"] = hashlib.sha256(data).hexdigest()
        except exceptions.InvalidAddressException as excp:
            data = None
            row["read"] = type(excp).__name__
            bad = int(excp.invalid_address)
            row["exception_layer"] = excp.layer_name
            row["exception_address"] = hex(bad)
            if excp.layer_name == layer.name:
                row["exception_page"] = "first" if bad < va + PAGE else "second"
            else:
                row["exception_page"] = "first" if bad >> 12 == slot else "lower_layer"
            totals["volatility_unreadable"] += 1
            totals[f"unreadable_{row['read']}"] += 1
        if data is not None and earlier:
            h = earlier.get((pid, va + offset, length))
            row["same_as_earlier"] = h == row["sha256"] if h else None
            totals["earlier_hash_" + {True: "same", False: "different", None: "missing"}[row["same_as_earlier"]]] += 1
        pf.seek(slot * PAGE)
        slot_page = pf.read(PAGE)
        direct = slot_page[offset:offset + length]
        slot_start = slot_page[:length]
        row["slot_page_one_byte_value"] = len(set(slot_page)) == 1
        row["slot_page_all_zero"] = slot_page == bytes(PAGE)
        row["first_page_bitmap"] = allocated(0, slot)
        if not crossing:
            row["slot_start_equals_offset_bytes"] = slot_start == direct
            row["offset_bytes_all_zero"] = direct == bytes(length)
            if data is not None:
                same = data == direct
                totals["inside_same_as_direct" if same else "inside_differs_from_direct"] += 1
                if data == slot_start and not same:
                    totals["inside_equals_slot_start_instead"] += 1
                if same:
                    totals["inside_same__slot_start_equal_" + str(slot_start == direct)] += 1
        else:
            second = where(layer, va + PAGE)
            row["second_page"] = second
            k = second.get("kind")
            if second.get("slot") is not None and k.startswith(("pf0_slot", "readable_swap")):
                row["second_page_adjacent_slot"] = second["slot"] == slot + 1
            if data is not None:
                totals["crossing_read"] += 1
                totals[f"crossing_ok_second_{k}"] += 1
            else:
                totals[f"crossing_unreadable_second_{k}"] += 1
        rows.append(row)
    report = {
        "volatility3": volatility3.__file__,
        "candidates": len(candidates),
        "sample": len(sample),
        "totals": dict(sorted(totals.items())),
        "reads": rows,
    }
    out.write_text(json.dumps(report, indent=1), encoding="utf-8", newline="\n")
    print(json.dumps({k: v for k, v in report.items() if k != "reads"}, indent=1))


if __name__ == "__main__":
    main()
