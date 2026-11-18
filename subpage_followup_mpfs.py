"""Read, with MemProcFS at the same address, the reads in the subpage_followup.py result that Volatility could not do.

For each read, three reads are made one at a time (FLAG_NOCACHE): the whole read, the part in the first page, and the part in the second page.
Each result is recorded as unreadable / zero-filled / bytes (hash), and counted together with the second-page kind that subpage_followup.py assigned.

Usage (MemProcFS virtual environment): subpage_followup_mpfs.py <memory> <pagefile.sys> <subpage_followup output> <output json>
"""
import hashlib
import json
import sys
from collections import Counter

import memprocfs

PAGE = 0x1000


def main():
    mem, pagefile, path, out = sys.argv[1:5]
    rows = json.load(open(path, encoding="utf-8"))["reads"]
    vmm = memprocfs.Vmm(["-device", mem, "-pagefile0", pagefile])

    def read(pid, va, length):
        try:
            data = vmm.process(pid).memory.read(va, length, memprocfs.FLAG_NOCACHE)
        except Exception:
            data = None
        if data is None or len(data) != length:
            return {"result": "unreadable"}
        if data == bytes(length):
            return {"result": "zero"}
        return {"result": "bytes", "sha256": hashlib.sha256(data).hexdigest()}

    totals, report_rows = Counter(), []
    for r in rows:
        if r["read"] == "ok":
            continue
        va = int(r["va"], 16)
        start, length = va + r["offset"], r["length"]
        first_len = min(length, va + PAGE - start)
        res = {
            "i": r["i"], "pid": r["pid"], "va": r["va"],
            "volatility": r["read"], "exception_page": r["exception_page"],
            "second_page_kind": r.get("second_page", {}).get("kind"),
            "whole": read(r["pid"], start, length),
            "first_part": read(r["pid"], start, first_len),
        }
        if length > first_len:
            res["second_part"] = read(r["pid"], va + PAGE, length - first_len)
        kind = res["second_page_kind"] or "first_page"
        totals[f"{kind}__whole_{res['whole']['result']}"] += 1
        if "second_part" in res:
            totals[f"{kind}__second_part_{res['second_part']['result']}"] += 1
        report_rows.append(res)
    report = {"memprocfs_version": getattr(memprocfs, "__version__", None), "rows": len(report_rows),
              "totals": dict(sorted(totals.items())), "reads": report_rows}
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=1)
    print(json.dumps({k: v for k, v in report.items() if k != "reads"}, indent=1))


if __name__ == "__main__":
    main()
