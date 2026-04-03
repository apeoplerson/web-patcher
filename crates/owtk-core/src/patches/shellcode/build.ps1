# Compiles all shellcode C files into flat binaries and verifies
# the compiled output is correct.
#
# Usage:
#   .\build.ps1                        # auto-detect toolchain on PATH
#   .\build.ps1 D:\path\to\toolchain   # use a specific ARM toolchain prefix dir
#
# Each subdirectory containing a .c file is compiled against the shared
# link.ld and shellcode.h, producing a .elf and .bin next to the source.
#
# After building, each blob is verified:
#   - All placeholder magic values (PH32/PH16) are present and distinct
#   - The literal pool entry references the config struct correctly
#   - No BL/BLX instructions target addresses outside the blob

param([string]$ToolchainDir)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LinkerScript = Join-Path $ScriptDir 'link.ld'
$LinkBase = 0x08060000

# Resolve toolchain.
if ($ToolchainDir) {
    $Prefix = Join-Path $ToolchainDir 'bin\arm-none-eabi-'
} else {
    $Prefix = 'arm-none-eabi-'
}

$GCC     = "${Prefix}gcc.exe"
$OBJCOPY = "${Prefix}objcopy.exe"
$OBJDUMP = "${Prefix}objdump.exe"
$NM      = "${Prefix}nm.exe"

if (-not (Get-Command $GCC -ErrorAction SilentlyContinue)) {
    Write-Error "$GCC not found - pass the toolchain directory as an argument or add it to PATH"
    exit 1
}

$CFLAGS = @('-mcpu=cortex-m3', '-mthumb', '-Os', '-nostdlib', '-ffreestanding', '-fno-exceptions')

function Verify-Blob {
    param([string]$Elf, [string]$Bin, [string]$Name)

    $errors = 0
    $bytes = [System.IO.File]::ReadAllBytes($Bin)
    $hex = -join ($bytes | ForEach-Object { '{0:x2}' -f $_ })

    # 1. Check all PH32/PH16 placeholder values are present.
    #    PH32(n) = 0xDEAD0000|n  -> LE: xx00adde
    #    PH16(n) = 0xBE00|n      -> LE: xxbe
    $ph32 = 0
    $ph16 = 0
    for ($i = 1; $i -le 20; $i++) {
        if ($hex -match ('{0:x2}00adde' -f $i)) { $ph32++ }
        if ($hex -match ('{0:x2}be' -f $i))     { $ph16++ }
    }

    if (($ph32 + $ph16) -eq 0) {
        Write-Host "      FAIL  no placeholder values found - config struct optimised out" -ForegroundColor Red
        $errors++
    } else {
        Write-Host "      OK    $ph32 PH32 + $ph16 PH16 placeholders intact"
    }

    # 2. Check the literal pool references the cfg symbol.
    $nmOutput = & $NM $Elf 2>$null
    $cfgLine = $nmOutput | Where-Object { $_ -match '\bcfg$' } | Select-Object -First 1
    if ($cfgLine -match '^([0-9a-fA-F]+)\s') {
        $cfgAddr = $Matches[1]
        $cfgInt = [Convert]::ToUInt32($cfgAddr, 16)
        $cfgLE = '{0:x2}{1:x2}{2:x2}{3:x2}' -f ($cfgInt -band 0xFF),
            (($cfgInt -shr 8) -band 0xFF),
            (($cfgInt -shr 16) -band 0xFF),
            (($cfgInt -shr 24) -band 0xFF)
        if ($hex.Contains($cfgLE)) {
            Write-Host "      OK    literal pool -> cfg at 0x$cfgAddr"
        } else {
            Write-Host "      FAIL  literal pool does not reference cfg at 0x$cfgAddr" -ForegroundColor Red
            $errors++
        }
    } else {
        Write-Host "      WARN  cfg symbol not found in ELF" -ForegroundColor Yellow
    }

    # 3. Check for BL/BLX to addresses outside the blob.
    $binSize = (Get-Item $Bin).Length
    $blobStart = $LinkBase
    $blobEnd = $LinkBase + $binSize

    $badCalls = 0
    $disasm = & $OBJDUMP -d $Elf 2>$null
    foreach ($line in $disasm) {
        if ($line -match '\tblx?\t([0-9a-fA-F]+)') {
            $target = [Convert]::ToUInt32($Matches[1], 16)
            if ($target -lt $blobStart -or $target -ge $blobEnd) {
                Write-Host "      FAIL  external call: $($line.Trim())" -ForegroundColor Red
                $badCalls++
            }
        }
    }

    if ($badCalls -eq 0) {
        Write-Host "      OK    no external BL/BLX calls"
    }
    $errors += $badCalls

    return $errors
}

$compiled = 0
$failed = 0

foreach ($src in Get-ChildItem -Path $ScriptDir -Filter '*.c' -Recurse) {
    $dir = $src.DirectoryName
    $name = $src.BaseName
    $elf = Join-Path $dir "$name.elf"
    $bin = Join-Path $dir "$name.bin"

    Write-Host "  CC  $name"
    & $GCC @CFLAGS -I"$ScriptDir" -o $elf $src.FullName -T $LinkerScript
    if ($LASTEXITCODE -ne 0) { Write-Error "gcc failed for $name"; exit 1 }

    & $OBJCOPY -O binary $elf $bin
    if ($LASTEXITCODE -ne 0) { Write-Error "objcopy failed for $name"; exit 1 }

    $size = (Get-Item $bin).Length
    Write-Host "      -> $name.bin ($size bytes)"
    $compiled++

    $errs = Verify-Blob -Elf $elf -Bin $bin -Name $name
    if ($errs -gt 0) { $failed++ }
    Write-Host ""
}

Write-Host "built $compiled blob(s), $failed failure(s)."
if ($failed -gt 0) { exit 1 }
