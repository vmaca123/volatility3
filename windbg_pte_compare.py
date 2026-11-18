"""See how WinDbg (kd) `!pte` decodes paged-out PTEs, and compare it with the four decoding rules.

The Microsoft debugger extension's decoding is used as an independent reference. kd only opens dump format (.dmp).
  make  : from pte_swizzle_probe.py raw data (.entries.json), pick software PTEs inside VADs per kind and write a kd command file
          (kind = SwizzleBit, mask bit, PageFileLow number, demand zero, PageFileHigh all ones). PID -> EPROCESS is read from
          a kd `!process 0 0` log.
  parse : read the kd log, extract PageFile and Offset (or DemandZero etc.) for each entry, and count matches with the four rules (M, F, X, V).
Usage: windbg_pte_compare.py make <.entries.json> <process-list.log> <sample json> <kd command file> [per kind]
       windbg_pte_compare.py parse <sample json> <kd log> <output json>
"""
import bisect
import json
import random
import re
import sys
from collections import Counter, defaultdict

MASK_HI = 0x2000            # InvalidPteMask >> 32; default for a mask of 0x200000000000 (the probe reads the real value)
# A dump from a different CPU can have a different value, so `make` reads it from the probe output (<name>.json) and writes it
# to the sample file, and `parse` reads it from the sample file. Older sample files without the value use the default above.


def set_mask(invalid_pte_mask):
    global MASK_HI
    if isinstance(invalid_pte_mask, str):           # the probe writes it as "0x200000000000"
        invalid_pte_mask = int(invalid_pte_mask, 16)
    MASK_HI = invalid_pte_mask >> 32


def decode(e, how):
    high = e >> 32
    swizzle = (e >> 4) & 1
    if how == "M":
        high = high if swizzle else high & ~MASK_HI
    elif how == "F":
        high &= ~MASK_HI
    elif how == "X":
        high ^= MASK_HI
    number = (e >> 1) & 0xF if how == "V" else (e >> 12) & 0xF
    return number, high


def kind(e):
    high = e >> 32
    if high == 0xFFFFFFFF:
        return f"high_all_ones_swz{(e >> 4) & 1}"
    n, h = decode(e, "M")
    if n == 0 and h == 0:
        return f"demand_zero_swz{(e >> 4) & 1}_mask{int(bool(high & MASK_HI))}"
    return f"pf{min(n, 3)}_swz{(e >> 4) & 1}_mask{int(bool(high & MASK_HI))}_bit7_{int(bool(e & 0x80))}"


def make(entries_path, plist_path, sample_path, script_path, per_kind=25):
    dump = json.load(open(entries_path, encoding="utf-8"))
    probe_path = entries_path.replace(".entries.json", ".json")
    invalid_pte_mask = json.load(open(probe_path, encoding="utf-8"))["invalid_pte_mask"]
    set_mask(invalid_pte_mask)
    vads = {int(k): v for k, v in dump["vads"].items()}
    starts = {p: [r[0] for r in rs] for p, rs in vads.items()}
    eproc = {}
    current = None
    if plist_path.endswith(".json"):
        # Instead of kd `!process 0 0`: Volatility `windows.pslist -r json` output (PID, Offset(V)). Volatility prints kernel
        # addresses without the upper ffff, so it is added back. Kept so that kd only has to be opened once
        for row in json.load(open(plist_path, encoding="utf-8")):
            eproc[int(row["PID"])] = f"{int(row['Offset(V)']) | 0xFFFF000000000000:016x}"
        plist_path = None
    for line in (open(plist_path, encoding="utf-8", errors="replace") if plist_path else []):
        m = re.match(r"PROCESS ([0-9a-f]{16})", line.strip())
        if m:
            current = m.group(1)
        m = re.search(r"Cid: ([0-9a-f]+)", line)
        if m and current:
            eproc[int(m.group(1), 16)] = current
            current = None

    def in_vad(p, va):
        rs = vads.get(p, [])
        i = bisect.bisect_right(starts.get(p, []), va)
        return i > 0 and rs[i - 1][0] <= va <= rs[i - 1][1]

    pools = defaultdict(list)
    for pid, va, e in dump["entries"]:
        if pid in eproc and in_vad(pid, va):
            pools[kind(e)].append((pid, va, e))
    rng = random.Random(20261107)
    sample = []
    for k in sorted(pools):
        picks = pools[k] if len(pools[k]) <= per_kind else rng.sample(pools[k], per_kind)
        sample += [{"kind": k, "pid": p, "va": va, "pte": e} for p, va, e in picks]
    sample.sort(key=lambda s: (s["pid"], s["va"]))
    lines, last = [], None
    for i, s in enumerate(sample):
        if s["pid"] != last:
            lines.append(f".process /p {eproc[s['pid']]}")
            last = s["pid"]
        lines.append(f".echo @@@ {i}")
        lines.append(f"!pte {s['va']:x}")
    lines.append(".echo @@@ end")
    with open(script_path, "w", encoding="ascii", newline="\r\n") as h:
        h.write("\n".join(lines) + "\n")
    json.dump({"invalid_pte_mask": invalid_pte_mask, "pool_sizes": {k: len(v) for k, v in sorted(pools.items())}, "sample": sample},
              open(sample_path, "w", encoding="utf-8"), indent=1)
    print(len(sample), "samples,", len(set(s["pid"] for s in sample)), "processes")


def parse(sample_path, log_path, out_path):
    data = json.load(open(sample_path, encoding="utf-8"))
    if "invalid_pte_mask" in data:
        set_mask(data["invalid_pte_mask"])
    sample = data["sample"]
    blocks, cur = {}, None
    for line in open(log_path, encoding="utf-8", errors="replace"):
        m = re.match(r"@@@ (\d+|end)", line.strip())
        if m:
            cur = None if m.group(1) == "end" else int(m.group(1))
            if cur is not None:
                blocks[cur] = []
            continue
        if cur is not None:
            blocks[cur].append(line.rstrip("\n"))
    table = Counter()
    rows = []
    for i, s in enumerate(sample):
        text = "\n".join(blocks.get(i, []))
        contains = re.findall(r"contains ([0-9A-Fa-f]{16})", text)
        pf = re.search(r"PageFile:\s*([0-9a-fA-F]+)", text)
        off = re.search(r"Offset:\s*([0-9a-fA-F]+)", text)
        row = {"i": i, "kind": s["kind"], "pte": f"{s['pte']:016x}",
               "windbg_pte": contains[-1].lower() if contains else None}
        if pf and off:
            row["windbg"] = [int(pf.group(1), 16), int(off.group(1), 16)]
            # PageFile 0 / Offset 0 is an entry that WinDbg shows as "Decommitted" etc., depending on the protection value
            if row["windbg"] == [0, 0]:
                row["windbg"] = "demand_zero"
                row["windbg_label"] = (re.search(r"Protect:\s*(.*)", text) or [None, None])[1]
        elif "DemandZero" in text:
            row["windbg"] = "demand_zero"
        else:
            row["windbg"] = "other"
            row["text_tail"] = [l.strip() for l in blocks.get(i, []) if l.strip()][-3:]
        same_pte = row["windbg_pte"] == row["pte"]
        for how in ("M", "F", "X", "V"):
            n, h = decode(s["pte"], how)
            ours = "demand_zero" if (n == 0 and h == 0) else [n, h]
            row[how] = ours == row["windbg"]
            table[(s["kind"], how, row[how])] += 1
        table[(s["kind"], "pte_read_same", same_pte)] += 1
        rows.append(row)
    summary = defaultdict(dict)
    for (k, how, ok), n in table.items():
        summary[k][f"{how}_{'match' if ok else 'differ'}"] = n
    totals = Counter()
    for (k, how, ok), n in table.items():
        totals[f"{how}_{'match' if ok else 'differ'}"] += n
    report = {"log": log_path, "samples": len(sample), "totals": dict(sorted(totals.items())),
              "by_kind": dict(sorted(summary.items())), "pool_sizes": data["pool_sizes"], "rows": rows}
    json.dump(report, open(out_path, "w", encoding="utf-8"), indent=1)
    print(json.dumps({"samples": len(sample), "totals": report["totals"]}, indent=1))
    for k, v in sorted(summary.items()):
        print(k, {x: v.get(x, 0) for x in ("pte_read_same_match", "M_match", "F_match", "X_match", "V_match")})


if __name__ == "__main__":
    if sys.argv[1] == "make":
        make(*sys.argv[2:6], *(int(x) for x in sys.argv[6:7]))
    else:
        parse(*sys.argv[2:5])
