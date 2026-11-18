# Memory pressure. Allocates $MB megabytes as 64MB blocks and writes a marker in every page (4KB) at the page start (0) and the middle (2048).
# Even blocks are filled with random bytes (not compressible -> go to pagefile), odd blocks with zeros (go to the compressed store), then the markers are written.
# Marker: "LABPAGE|<Id>|<block>|<page>|<offset>|" - used at analysis time to judge whether page content read from the page file is right.
param([int]$Id, [int]$MB)
$block = 64MB
$count = [math]::Floor($MB * 1MB / $block)
$keep = New-Object System.Collections.ArrayList
$rng = New-Object System.Random ($Id * 7919 + 1)
$ascii = [System.Text.Encoding]::ASCII
for ($b = 0; $b -lt $count; $b++) {
    $buf = New-Object byte[] $block
    if ($b % 2 -eq 0) { $rng.NextBytes($buf) }
    for ($p = 0; $p -lt ($block / 4096); $p++) {
        foreach ($off in 0, 2048) {
            $m = $ascii.GetBytes(("LABPAGE|{0}|{1}|{2}|{3}|" -f $Id, $b, $p, $off))
            [System.Buffer]::BlockCopy($m, 0, $buf, $p * 4096 + $off, $m.Length)
        }
    }
    [void]$keep.Add($buf)
}
Set-Content ("C:\lab\done-{0}.txt" -f $Id) ("{0} blocks of 64MB" -f $count)
while ($true) { Start-Sleep 3600; [void]$keep.Count }
