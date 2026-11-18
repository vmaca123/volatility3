# Verification scripts for volatility3 PR #2080 (Windows page file PTE decoding)

These are English copies of the scripts used to check how paged-out (software) PTEs are decoded on Windows x64.
Only comments and docstrings were translated. Program logic, argument order, random seeds and JSON keys are the same as in the originals, so outputs stay comparable.

## Requirements

- **Volatility 3**: `pte_swizzle_probe.py`, `subpage_read_check.py`, `subpage_followup.py` and `marker_check.py` import `volatility3`. Put the checkout of the branch under test on `PYTHONPATH`:
  - POSIX shell: `PYTHONPATH=/path/to/volatility3 python subpage_read_check.py ...`
  - PowerShell: `$env:PYTHONPATH = "C:\path\to\volatility3"; python subpage_read_check.py ...`
- **`memprocfs` Python package**: `mpfs_read_compare.py` and `subpage_followup_mpfs.py`. Both open the image with `-device <memory> -pagefile0 <pagefile.sys>`.
- **kd / WinDbg**: `windbg_pte_compare.py` writes a kd command file and parses the kd log. kd needs the memory in dump format (`.dmp`).
- `windbg_pte_compare.py` and `allocated_bit_check.py` use only the Python standard library.
- `pressure.ps1` runs inside a Windows test VM (Windows PowerShell, `powershell.exe`).

## Order

1. (VM test only) Run `pressure.ps1` in the guest, then capture memory and `pagefile.sys`.
2. `pte_swizzle_probe.py` - steps 3, 4, 5 and 7 build on its output.
3. `windbg_pte_compare.py make` -> run the command file in kd -> `windbg_pte_compare.py parse`
4. `subpage_read_check.py` -> `mpfs_read_compare.py`
5. `subpage_followup.py` (with `--earlier` = output of step 4) -> `subpage_followup_mpfs.py`
6. (VM test only) `marker_check.py`
7. `allocated_bit_check.py` (needs step 2, and step 6 for the marker check)
8. `bit7_protection_split.py` and `pfn_original_pte_slots.py` (need step 2)
9. `slot_owner_scan.py` (needs steps 2 and 8) and `mpfs_allocated0_markers.py` (needs steps 2 and 6)
10. `mpfs_marker_slot_state.py` (needs steps 2 and 9) and `marker_commit5_diff.py` (needs step 2 and two runs of step 6)

Steps 3, 4 and 6 do not depend on each other.

## Scripts

**pressure.ps1** - In-guest script that writes markers and fills memory so pages get pushed out.
Run: `powershell -File pressure.ps1 -Id <n> -MB <megabytes>` (one or more instances with different `-Id` values).
It allocates `floor(MB / 64)` byte arrays of 64MB. Even-numbered blocks are filled with random bytes (`System.Random(Id * 7919 + 1)`), odd-numbered blocks stay zero.
In every 4KB of each array it writes `LABPAGE|<Id>|<block>|<page>|<offset>|` at array offsets 0 and 2048.
When done it writes `C:\lab\done-<Id>.txt`; the folder `C:\lab` must exist in the guest for that file to be written (the path only affects this status file, not the markers).
It then sleeps forever to keep the arrays in memory; capture memory and `pagefile.sys` while it runs.

**pte_swizzle_probe.py** - Reads a memory image. Uses Volatility 3 to load kernel symbols and list processes, but walks the user-space page tables itself on the physical layer.
Run: `python pte_swizzle_probe.py <memory image> <out.json>`.
Writes `<out.json>` (InvalidPteMask, `_MMPTE_SOFTWARE` bit layout, page file list with AllocationBitmap summary, walk counters, and per-rule results M / F / X / V for all software PTEs and for those inside VADs) and `<out.entries.json>` (raw `(pid, va, pte)` list, VAD ranges per process, AllocationBitmap bytes per page file as hex).
Give the output a `.json` name and keep both files in the same folder: the other scripts take the `.entries.json` path and find the probe JSON by replacing `.entries.json` with `.json`.

**windbg_pte_compare.py** - Compares WinDbg's `!pte` decoding with the rules M / F / X / V.
`make`: `python windbg_pte_compare.py make <x.entries.json> <process list> <sample.json> <kd command file> [per kind]`.
Reads `<x.entries.json>` and `<x.json>` from `pte_swizzle_probe.py`. The process list is either a kd `!process 0 0` log or Volatility `windows.pslist -r json` output (a file name ending in `.json`).
It picks up to `per kind` (default 25) software PTEs inside VADs per PTE kind, for processes in the process list (seed 20261107), and writes the sample JSON and a kd command file (`.process /p`, `!pte`, `.echo @@@ <i>` separators).
Run the command file in kd against the same `.dmp` and save the console output to a log file.
`parse`: `python windbg_pte_compare.py parse <sample.json> <kd log> <out.json>` writes per-sample WinDbg PageFile / Offset and whether each rule matches.
The decoding in this script uses fixed bit positions (SwizzleBit = bit 4, PageFileLow = bits 12-15); the InvalidPteMask comes from the probe JSON.

**subpage_read_check.py** - Reads paged-out pages from the middle of the page through the Volatility process layer.
Run: `python subpage_read_check.py <memory image> <pagefile.sys> <x.entries.json> <out.json> [sample size]` (default 600).
Candidates are `pagefile.sys` (page file number 0) PTEs inside VADs with non-zero protection, PageFileHigh not all ones, and a slot inside the file size. The sample is drawn with `random.Random(20261108)`.
Every fourth read (`i % 4 == 3`) crosses into the next page; the others end inside the page and are also compared with the bytes read directly from `pagefile.sys` at `slot * 4096 + offset`.
Writes totals and one row per read that Volatility could do: `[pid, address, length, sha256, crossing]`. Needs `pte_swizzle_probe.py` output.

**mpfs_read_compare.py** - Reads the same reads again with MemProcFS (`FLAG_NOCACHE`) and compares the SHA-256 hashes.
Run: `python mpfs_read_compare.py <memory image> <pagefile.sys> <subpage_read_check out.json> <out.json>`.
Needs `subpage_read_check.py` output and the `memprocfs` package.

**subpage_followup.py** - Draws the same sample as `subpage_read_check.py` again and records more detail per read: the exception type, layer and address and whether it failed in the first or second page; for crossing reads, where the second page is and its PTE kind; whether the slot-start bytes equal the bytes at the offset; whether the slot page is a single byte value; and the AllocationBitmap bit of the slot.
PTE kinds are decoded from the kernel layout stored in the probe JSON, not from Volatility's decoding.
Run: `python subpage_followup.py <memory image> <pagefile.sys> <x.entries.json> <out.json> [--earlier <subpage_read_check out.json>] [--sample N]`.
It must keep the same candidate rule and the same order of random calls as `subpage_read_check.py`, so that it reproduces the same sample (seed 20261108). Use the same sample size as for `subpage_read_check.py` (default 600 in both). With `--earlier`, the `earlier_hash_*` totals show whether the read bytes match the earlier run.
Needs `pte_swizzle_probe.py` output (and `subpage_read_check.py` output for `--earlier`).

**subpage_followup_mpfs.py** - For the reads that Volatility could not do in `subpage_followup.py`, reads the whole range, the part in the first page and the part in the second page with MemProcFS (`FLAG_NOCACHE`), and records each as unreadable / zero / bytes (sha256), counted by the second-page kind.
Run: `python subpage_followup_mpfs.py <memory image> <pagefile.sys> <subpage_followup out.json> <out.json>`.
Needs `subpage_followup.py` output and the `memprocfs` package.

**marker_check.py** - For images captured while `pressure.ps1` ran. Reads every 4KB page of large (32MB or more) private VADs in `powershell.exe` processes through Volatility and checks the markers.
Each page is classified by where it was read from (memory / swap layer / `swapped_pfN` / paged / invalid), by verdict (good / misplaced / bad / zero / no_marker / unreadable), and as `in_array` or `outside`.
Run: `python marker_check.py <memory image> <out.json> [pagefile.sys ...]` (page files are passed to Volatility as swap layers).
Writes `<out.json>` and `<out.json>.raw.json.gz` (raw records for recounting; input for `allocated_bit_check.py`). It also records the kernel layer's `page_file_low_bit`, `swizzle_bit` and `invalid_pte_mask` config values as `layer_settings` (null where the Volatility version does not set them).

**allocated_bit_check.py** - Checks `pagefile.sys` (number 0) PTEs inside VADs, split by the `PageFileAllocated` bit: the AllocationBitmap bit of the slot, whether another PTE points to the same slot, protection values and `PageFileReserved`. With marker data, it checks whether a page read from the page file with `PageFileAllocated` 0 and a marker pair shares its marker with a `PageFileAllocated` 1 PTE on the same slot. It uses neither Volatility nor MemProcFS.
Run: `python allocated_bit_check.py <out.json> <name>=<x.entries.json>[,<marker_check out.json.raw.json.gz>] [...]`.
Needs `pte_swizzle_probe.py` output, and `marker_check.py` raw output for the marker part. Images whose `_MMPTE_SOFTWARE` has no `PageFileAllocated` are reported as skipped.

**bit7_protection_split.py** - Splits `pagefile.sys` and other page file PTEs inside VADs by protection value and bit 7, with the AllocationBitmap bit of each slot, the page file number, `PageFileReserved` / `PageFileAllocated`, and how many processes and VADs they come from. It uses neither Volatility nor MemProcFS.
Run: `python bit7_protection_split.py <out.json> <name>=<x.entries.json> [...]`. Needs `pte_swizzle_probe.py` output.

**pfn_original_pte_slots.py** - Reads the `_MMPFN` array and collects the page file slots named by `OriginalPte` of pages on the active, standby, modified, modified no-write and transition lists. It then matches them with the `pagefile.sys` PTEs inside VADs from `pte_swizzle_probe.py`. This shows whether a slot that no PTE with `PageFileAllocated` set names is held by a page that is in memory.
Run: `python pfn_original_pte_slots.py <memory image> <x.entries.json> <out.json>`. Uses Volatility 3 for the kernel symbols and the PFN database address (`MmPfnDatabase`); the last PFN is taken from the end of the physical layer.

**slot_owner_scan.py** - For page file slots that PTEs with `PageFileAllocated` clear name, and that the AllocationBitmap marks as used, looks for an owner anywhere: every 8-byte value in the dump's physical layer and in `pagefile.sys` that is shaped like a software PTE with `PageFileAllocated` set and that slot number. Memory hits are split into inside and outside the PFN database. Two control groups of the same size show the method's rates: slots owned by a walked process PTE (should be found), and free slots (chance matches).
Run: `python slot_owner_scan.py <memory image> <pagefile.sys> <x.entries.json> <pfn_original_pte_slots out.json> <out.json>`. Uses Volatility 3 and numpy.

**mpfs_allocated0_markers.py** - Takes the pages that `marker_check.py` read from the page file with a marker pair while their PTE had `PageFileAllocated` clear, reads each with MemProcFS (`FLAG_NOCACHE`, one page at a time), and counts whether MemProcFS returns the same marker, and whether a PTE with the bit set on the same slot has that marker as its own.
Run: `python mpfs_allocated0_markers.py <memory image> <pagefile.sys> <x.entries.json> <marker_check out.json.raw.json.gz> <out.json>`. Needs the `memprocfs` package.

**mpfs_marker_slot_state.py** - Splits the pages in `mpfs_allocated0_markers.py` output by the state of their slot: in use or free in AllocationBitmap, also named by another PTE with `PageFileAllocated` set (and whether that PTE is in another process), and whether the marker check read the same marker from that PTE's page (that is, the page sits at the marker's array position). It uses neither Volatility nor MemProcFS.
Run: `python mpfs_marker_slot_state.py <out.json> <name>=<mpfs_allocated0_markers out.json>,<x.entries.json> [...]`.

**marker_commit5_diff.py** - Compares two `marker_check.py` runs on the same image page by page, e.g. before and with the `PageFileAllocated` commit. For every page the first run read from a page file (any swap layer), it records whether the second run read it from the same place, could not read it, or read it from elsewhere, split by what the first run found on the page (marker pair, bad, no_marker, zero) and the page's `PageFileAllocated` bit. It also counts pages that only the second run reads from a page file. It uses neither Volatility nor MemProcFS.
Run: `python marker_commit5_diff.py <first .raw.json.gz> <second .raw.json.gz> <x.entries.json> <out.json>`.

## Notes

- Output JSON contains local paths: `image` (the memory image) and `volatility3` (the imported package file).
- `.entries.json` and `.raw.json.gz` hold raw data from the image (process IDs, virtual addresses or page numbers, PTE values, bitmap bytes, marker fields).
