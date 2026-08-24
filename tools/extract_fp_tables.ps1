# Extract byte/int table data from upstream Go source files into Rust const
# fragments, to avoid transcription errors on the ~4KB of FairPlay tables.
$ErrorActionPreference = "Stop"

function Get-GoFile([string]$name) {
    Get-Content "C:\Users\USER.DESKTOP-6082GBO\doubletake-upstream\internal\airplay\$name" -Raw
}

# Returns the body inside the first '{...}' block whose opening brace follows
# the given regex match position.
function Get-BraceBody([string]$src, [System.Text.RegularExpressions.Match]$m) {
    $start = $m.Index + $m.Length
    $depth = 1
    $i = $start
    while ($i -lt $src.Length -and $depth -gt 0) {
        $c = $src[$i]
        if ($c -eq '{') { $depth++ }
        elseif ($c -eq '}') { $depth-- }
        $i++
    }
    if ($depth -ne 0) { throw "unbalanced braces after match at $($m.Index)" }
    return $src.Substring($start, $i - $start - 1)
}

function Extract-SimpleBytes([string]$src, [string]$varName) {
    $pattern = "var\s+$varName\s*=\s*\[[^\r\n]*\](byte|uint8)\{"
    $m = [regex]::Match($src, $pattern)
    if (-not $m.Success) { throw "var $varName not found" }
    $body = Get-BraceBody $src $m
    # Strip Go comments so decimal literals in comments are not captured.
    $body = $body -replace '(?m)//.*$', ''
    # Hex literals (0x..) or standalone decimal literals (position maps).
    # The decimal alternative requires non-word chars on both sides so digits
    # inside identifiers (e.g. fpsapM1Capabilities) are not captured.
    $vals = [regex]::Matches($body, "0x([0-9a-fA-F]{2})|(?<![0-9a-fA-Fx\w])(\d+)(?![\w.])") | ForEach-Object {
        if ($_.Groups[1].Success) { [Convert]::ToByte($_.Groups[1].Value, 16) }
        else { [Convert]::ToByte([int]$_.Groups[2].Value) }
    }
    return ,$vals
}

function Extract-Ints([string]$src, [string]$varName) {
    $pattern = "var\s+$varName\s*=\s*\[[^\r\n]*\]int\{"
    $m = [regex]::Match($src, $pattern)
    if (-not $m.Success) { throw "var $varName (int) not found" }
    $body = Get-BraceBody $src $m
    $vals = [regex]::Matches($body, "\b(\d+)\b") | ForEach-Object { [int]$_.Groups[1].Value }
    return ,$vals
}

function Extract-Uint32s([string]$src, [string]$varName) {
    $pattern = "var\s+$varName\s*=\s*\[[^\r\n]*\]uint32\{"
    $m = [regex]::Match($src, $pattern)
    if (-not $m.Success) { throw "var $varName (uint32) not found" }
    $body = Get-BraceBody $src $m
    $vals = [regex]::Matches($body, "0x([0-9a-fA-F]{8})") | ForEach-Object { [Convert]::ToUInt32($_.Groups[1].Value, 16) }
    return ,$vals
}

function Extract-SapState([string]$src) {
    $m = [regex]::Match($src, "var\s+sapInitialState\s*=\s*sapState\{")
    if (-not $m.Success) { throw "sapInitialState not found" }
    $body = Get-BraceBody $src $m
    $hashM = [regex]::Match($body, "hash:\s*\[20\]byte\{")
    if (-not $hashM.Success) { throw "sapInitialState hash not found" }
    $hashBody = Get-BraceBody $body $hashM
    $matM = [regex]::Match($body, "matrix:\s*\[35\]byte\{")
    if (-not $matM.Success) { throw "sapInitialState matrix not found" }
    $matBody = Get-BraceBody $body $matM
    $hashVals = [regex]::Matches($hashBody, "0x([0-9a-fA-F]{2})") | ForEach-Object { [Convert]::ToByte($_.Groups[1].Value, 16) }
    $matVals = [regex]::Matches($matBody, "0x([0-9a-fA-F]{2})") | ForEach-Object { [Convert]::ToByte($_.Groups[1].Value, 16) }
    return ,@($hashVals, $matVals)
}

function Extract-Triples([string]$src, [string]$varName) {
    $m = [regex]::Match($src, "var\s+$varName\s*=\s*fpsapNetworkTables\{")
    if (-not $m.Success) { throw "var $varName (tables) not found" }
    $body = Get-BraceBody $src $m
    $triples = [regex]::Matches($body, "\{(\d+),\s*(0x[0-9a-fA-F]{2}),\s*(0x[0-9a-fA-F]{2})\}")
    $result = @()
    foreach ($t in $triples) {
        $result += ,@([int]$t.Groups[1].Value, [Convert]::ToByte($t.Groups[2].Value.Substring(2), 16), [Convert]::ToByte($t.Groups[3].Value.Substring(2), 16))
    }
    return ,$result
}

function Emit-Bytes([byte[]]$vals, [string]$indent, [int]$perLine = 12) {
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $vals.Length; $i += $perLine) {
        $chunk = $vals[$i..([Math]::Min($i + $perLine - 1, $vals.Length - 1))]
        $line = ($chunk | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", "
        [void]$sb.AppendLine("$indent$line,")
    }
    return $sb.ToString().TrimEnd("`r", "`n", " ", ",") + ","
}

$md5src = Get-GoFile "fairplay_md5.go"
$msgSrc = Get-GoFile "fairplay_message.go"
$cryptoSrc = Get-GoFile "fairplay_crypto.go"
$sapSrc = Get-GoFile "fairplay_sap.go"
$fpsapSrc = Get-GoFile "fpsap.go"
$tablesSrc = Get-GoFile "fpsap_tables.go"

$out = New-Object System.Text.StringBuilder

# ---- fairplay_md5.go ----
$shift = Extract-Ints $md5src "fairplayMD5Shift"
$consts = Extract-Uint32s $md5src "fairplayMD5Constant"
[void]$out.AppendLine("// Auto-generated from fairplay_md5.go")
[void]$out.AppendLine("pub const FAIRPLAY_MD5_SHIFT: [u32; $($shift.Length)] = [")
for ($i = 0; $i -lt $shift.Length; $i += 16) {
    $chunk = $shift[$i..([Math]::Min($i + 15, $shift.Length - 1))]
    [void]$out.AppendLine("    " + (($chunk | ForEach-Object { "$_" }) -join ", ") + ",")
}
[void]$out.AppendLine("];")
[void]$out.AppendLine("pub const FAIRPLAY_MD5_CONSTANT: [u32; $($consts.Length)] = [")
for ($i = 0; $i -lt $consts.Length; $i += 8) {
    $chunk = $consts[$i..([Math]::Min($i + 7, $consts.Length - 1))]
    [void]$out.AppendLine("    " + (($chunk | ForEach-Object { "0x{0:x8}" -f $_ }) -join ", ") + ",")
}
[void]$out.AppendLine("];")

# ---- fairplay_message.go ----
$invSBox = Extract-SimpleBytes $msgSrc "inverseAESSBox"
[void]$out.AppendLine("// Auto-generated from fairplay_message.go")
[void]$out.AppendLine("pub const INVERSE_AES_SBOX: [u8; $($invSBox.Length)] = [")
[void]$out.Append((Emit-Bytes $invSBox "    "))
[void]$out.AppendLine("];")
$ivs = Extract-SimpleBytes $msgSrc "fairplayMessageIV"
$rk0 = Extract-SimpleBytes $msgSrc "fairplayMessageRoundKey0"
$rk10 = Extract-SimpleBytes $msgSrc "fairplayMessageRoundKey10"
$mid = Extract-SimpleBytes $msgSrc "fairplayMessageMiddleKeys"
[void]$out.AppendLine("pub const FAIRPLAY_MESSAGE_IV: [[u8; 16]; $($ivs.Length / 16)] = [")
for ($i = 0; $i -lt $ivs.Length; $i += 16) {
    $chunk = $ivs[$i..($i + 15)]
    [void]$out.AppendLine("    [" + (($chunk | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", ") + "],")
}
[void]$out.AppendLine("];")
foreach ($pair in @(@("FAIRPLAY_MESSAGE_ROUND_KEY_0", $rk0), @("FAIRPLAY_MESSAGE_ROUND_KEY_10", $rk10))) {
    [void]$out.AppendLine("pub const $($pair[0]): [u8; 16] = [")
    [void]$out.AppendLine("    " + (($pair[1] | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", ") + ",")
    [void]$out.AppendLine("];")
}
[void]$out.AppendLine("pub const FAIRPLAY_MESSAGE_MIDDLE_KEYS: [[[u8; 16]; 9]; 4] = [")
for ($mode = 0; $mode -lt 4; $mode++) {
    [void]$out.AppendLine("    [")
    for ($round = 0; $round -lt 9; $round++) {
        $base = (($mode * 9) + $round) * 16
        $chunk = $mid[$base..($base + 15)]
        [void]$out.AppendLine("        [" + (($chunk | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", ") + "],")
    }
    [void]$out.AppendLine("    ],")
}
[void]$out.AppendLine("];")

# ---- fairplay_crypto.go ----
foreach ($pair in @(@("FAIRPLAY_INITIAL_SESSION_KEY", (Extract-SimpleBytes $cryptoSrc "fairplayInitialSessionKey")), @("FAIRPLAY_KDF_PREFIX", (Extract-SimpleBytes $cryptoSrc "fairplayKDFPrefix")), @("FAIRPLAY_KDF_SUFFIX", (Extract-SimpleBytes $cryptoSrc "fairplayKDFSuffix")))) {
    [void]$out.AppendLine("// Auto-generated from fairplay_crypto.go")
    [void]$out.AppendLine("pub const $($pair[0]): [u8; $($pair[1].Length)] = [")
    [void]$out.Append((Emit-Bytes $pair[1] "    "))
    [void]$out.AppendLine("];")
}

# ---- fairplay_sap.go ----
$sapState = Extract-SapState $sapSrc
$hash20 = $sapState[0]
$matrix35 = $sapState[1]
[void]$out.AppendLine("// Auto-generated from fairplay_sap.go")
[void]$out.AppendLine("pub const SAP_INITIAL_HASH: [u8; 20] = [")
[void]$out.Append((Emit-Bytes $hash20 "    "))
[void]$out.AppendLine("];")
[void]$out.AppendLine("pub const SAP_INITIAL_MATRIX: [u8; 35] = [")
[void]$out.Append((Emit-Bytes $matrix35 "    "))
[void]$out.AppendLine("];")
$seed = Extract-SimpleBytes $sapSrc "sapSeed"
[void]$out.AppendLine("pub const SAP_SEED: [u8; $($seed.Length)] = [")
[void]$out.Append((Emit-Bytes $seed "    "))
[void]$out.AppendLine("];")

# ---- fpsap.go ----
foreach ($pair in @(@("FPSAP_M1_PAYLOAD", (Extract-SimpleBytes $fpsapSrc "fpsapM1Payload")), @("FPSAP_M3_LABEL", (Extract-SimpleBytes $fpsapSrc "fpsapM3Label")), @("FPSAP_DESCRIPTOR_PREFIX", (Extract-SimpleBytes $fpsapSrc "fpsapDescriptorPrefix")), @("FPSAP_DESCRIPTOR_SUFFIX", (Extract-SimpleBytes $fpsapSrc "fpsapDescriptorSuffix")), @("FPSAP_FIXED_BLOCK", (Extract-SimpleBytes $fpsapSrc "fpsapFixedBlock")), @("FPSAP_FIRST_POSITION_MAP", (Extract-SimpleBytes $fpsapSrc "fpsapFirstPositionMap")), @("FPSAP_SECOND_POSITION_MAP", (Extract-SimpleBytes $fpsapSrc "fpsapSecondPositionMap")))) {
    [void]$out.AppendLine("// Auto-generated from fpsap.go")
    [void]$out.AppendLine("pub const $($pair[0]): [u8; $($pair[1].Length)] = [")
    [void]$out.Append((Emit-Bytes $pair[1] "    "))
    [void]$out.AppendLine("];")
}

# ---- fpsap_tables.go ----
$inMask = Extract-SimpleBytes $tablesSrc "fpsapFirstInputMask"
$outMask = Extract-SimpleBytes $tablesSrc "fpsapSecondOutputMask"
[void]$out.AppendLine("// Auto-generated from fpsap_tables.go")
[void]$out.AppendLine("pub const FPSAP_FIRST_INPUT_MASK: [u8; 16] = [")
[void]$out.Append((Emit-Bytes $inMask "    "))
[void]$out.AppendLine("];")
[void]$out.AppendLine("pub const FPSAP_SECOND_OUTPUT_MASK: [u8; 16] = [")
[void]$out.Append((Emit-Bytes $outMask "    "))
[void]$out.AppendLine("];")

$subBases = Extract-SimpleBytes $tablesSrc "fpsapSubstitutionBases"
[void]$out.AppendLine("pub const FPSAP_SUBSTITUTION_BASES: [[u8; 256]; $($subBases.Length / 256)] = [")
for ($i = 0; $i -lt $subBases.Length; $i += 256) {
    [void]$out.AppendLine("    [")
    [void]$out.Append((Emit-Bytes ($subBases[$i..($i + 255)]) "        "))
    [void]$out.AppendLine("    ],")
}
[void]$out.AppendLine("];")

$mixBases = Extract-SimpleBytes $tablesSrc "fpsapMixBases"
[void]$out.AppendLine("pub const FPSAP_MIX_BASES: [[u8; 256]; $($mixBases.Length / 256)] = [")
for ($i = 0; $i -lt $mixBases.Length; $i += 256) {
    [void]$out.AppendLine("    [")
    [void]$out.Append((Emit-Bytes ($mixBases[$i..($i + 255)]) "        "))
    [void]$out.AppendLine("    ],")
}
[void]$out.AppendLine("];")

# Network tables: triples {table, inputXOR, outputXOR} in order:
# roundSubstitution (9x16), mixColumns (4x4), finalSubstitution (16) — per network.
function Emit-NetworkTables([string]$rustName, $triples) {
    if ($triples.Length -ne 176) { throw "${rustName}: expected 176 triples, got $($triples.Length)" }
    $rs = $triples[0..143]
    $mc = $triples[144..159]
    $fs = $triples[160..175]
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("pub const ${rustName}: FpsapNetworkTables = FpsapNetworkTables {")
    [void]$sb.AppendLine("    round_substitution: [")
    for ($r = 0; $r -lt 9; $r++) {
        [void]$sb.AppendLine("        [")
        $row = $rs[($r * 16)..($r * 16 + 15)]
        foreach ($t in $row) {
            [void]$sb.AppendLine("            FpsapByteLookup { table: $($t[0]), input_xor: 0x$('{0:x2}' -f $t[1]), output_xor: 0x$('{0:x2}' -f $t[2]) },")
        }
        [void]$sb.AppendLine("        ],")
    }
    [void]$sb.AppendLine("    ],")
    [void]$sb.AppendLine("    mix_columns: [")
    for ($r = 0; $r -lt 4; $r++) {
        [void]$sb.AppendLine("        [")
        $row = $mc[($r * 4)..($r * 4 + 3)]
        foreach ($t in $row) {
            [void]$sb.AppendLine("            FpsapByteLookup { table: $($t[0]), input_xor: 0x$('{0:x2}' -f $t[1]), output_xor: 0x$('{0:x2}' -f $t[2]) },")
        }
        [void]$sb.AppendLine("        ],")
    }
    [void]$sb.AppendLine("    ],")
    [void]$sb.AppendLine("    final_substitution: [")
    foreach ($t in $fs) {
        [void]$sb.AppendLine("        FpsapByteLookup { table: $($t[0]), input_xor: 0x$('{0:x2}' -f $t[1]), output_xor: 0x$('{0:x2}' -f $t[2]) },")
    }
    [void]$sb.AppendLine("    ],")
    [void]$sb.AppendLine("};")
    return $sb.ToString()
}

$firstTriples = Extract-Triples $tablesSrc "fpsapFirstTables"
$secondTriples = Extract-Triples $tablesSrc "fpsapSecondTables"
[void]$out.AppendLine("// Auto-generated from fpsap_tables.go (network lookup tables)")
[void]$out.AppendLine("pub struct FpsapByteLookup { pub table: u8, pub input_xor: u8, pub output_xor: u8 }")
[void]$out.AppendLine("pub struct FpsapNetworkTables {")
[void]$out.AppendLine("    pub round_substitution: [[FpsapByteLookup; 16]; 9],")
[void]$out.AppendLine("    pub mix_columns: [[FpsapByteLookup; 4]; 4],")
[void]$out.AppendLine("    pub final_substitution: [FpsapByteLookup; 16],")
[void]$out.AppendLine("}")
[void]$out.Append((Emit-NetworkTables "FPSAP_FIRST_TABLES" $firstTriples))
[void]$out.Append((Emit-NetworkTables "FPSAP_SECOND_TABLES" $secondTriples))

$target = "C:\Users\USER.DESKTOP-6082GBO\doubletake-rs\dt-airplay\src\fp_tables_generated.rs"
[System.IO.File]::WriteAllText($target, $out.ToString())
Write-Host "Wrote $target ($($out.Length) chars)"
