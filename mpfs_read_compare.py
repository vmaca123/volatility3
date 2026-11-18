"""Read the random offset/length reads made by subpage_read_check.py again with MemProcFS (same process, address and length) and compare them.

Usage (MemProcFS virtual environment): mpfs_read_compare.py <memory.mem> <pagefile.sys> <subpage_read_check output> <output json>
"""
import hashlib
import json
import sys
from collections import Counter

import memprocfs


def main():
    mem, pagefile, reads_path, out = sys.argv[1:5]
    reads = json.load(open(reads_path, encoding="utf-8"))["reads"]
    vmm = memprocfs.Vmm(["-device", mem, "-pagefile0", pagefile])
    totals = Counter()
    for pid, va, length, h, crossing in reads:
        kind = "crossing" if crossing else "inside"
        try:
            data = vmm.process(pid).memory.read(va, length, memprocfs.FLAG_NOCACHE)
        except Exception:
            data = None
        if data is None or len(data) != length:
            totals[kind + "_memprocfs_unreadable"] += 1
        elif hashlib.sha256(data).hexdigest() == h:
            totals[kind + "_same"] += 1
        elif data == bytes(length):
            totals[kind + "_memprocfs_zero"] += 1
        else:
            totals[kind + "_different"] += 1
    report = {"reads": len(reads), "totals": dict(totals)}
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=1)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
