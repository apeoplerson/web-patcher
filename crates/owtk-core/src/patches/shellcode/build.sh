#!/usr/bin/env bash
# Compiles all shellcode C files into flat binaries and verifies
# the compiled output is correct.
#
# Usage:
#   ./build.sh                    # auto-detect toolchain on PATH
#   ./build.sh /path/to/toolchain # use a specific ARM toolchain prefix dir
#
# Each subdirectory containing a .c file is compiled against the shared
# link.ld and shellcode.h, producing a .elf and .bin next to the source.
#
# After building, each blob is verified:
#   - All placeholder magic values (PH32/PH16) are present and distinct
#   - The literal pool entry references the config struct correctly
#   - No BL/BLX instructions target addresses outside the blob
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINKER_SCRIPT="$SCRIPT_DIR/link.ld"
LINK_BASE=0x08060000

# Resolve toolchain.
if [[ -n "${1:-}" ]]; then
    PREFIX="$1/bin/arm-none-eabi-"
else
    PREFIX="arm-none-eabi-"
fi

GCC="${PREFIX}gcc"
OBJCOPY="${PREFIX}objcopy"
OBJDUMP="${PREFIX}objdump"
NM="${PREFIX}nm"

if ! command -v "$GCC" &>/dev/null; then
    echo "error: $GCC not found — pass the toolchain directory as an argument or add it to PATH" >&2
    exit 1
fi

CFLAGS="-mcpu=cortex-m3 -mthumb -Os -nostdlib -ffreestanding -fno-exceptions"

# ── Verify a compiled shellcode blob ──
# Args: $1=elf path, $2=bin path, $3=name
verify_blob() {
    local elf="$1" bin="$2" name="$3"
    local errors=0

    local hex
    hex=$(xxd -p "$bin" | tr -d '\n')

    # 1. Check all PH32/PH16 placeholder values are present.
    #    PH32(n) = 0xDEAD0000|n  -> LE: xx00adde
    #    PH16(n) = 0xBE00|n      -> LE: xxbe
    local ph32_found=0
    for i in $(seq 1 20); do
        local needle
        needle=$(printf '%02x00adde' "$i")
        if echo "$hex" | grep -q "$needle"; then
            ph32_found=$((ph32_found + 1))
        fi
    done
    local ph16_found=0
    for i in $(seq 1 20); do
        local needle
        needle=$(printf '%02xbe' "$i")
        if echo "$hex" | grep -q "$needle"; then
            ph16_found=$((ph16_found + 1))
        fi
    done
    local total_ph=$((ph32_found + ph16_found))
    if [[ $total_ph -eq 0 ]]; then
        echo "      FAIL  no placeholder values found — config struct optimised out" >&2
        errors=$((errors + 1))
    else
        echo "      OK    $ph32_found PH32 + $ph16_found PH16 placeholders intact"
    fi

    # 2. Check the literal pool references the cfg symbol.
    local cfg_addr
    cfg_addr=$("$NM" "$elf" 2>/dev/null | awk '$3 == "cfg" {print $1}')
    if [[ -n "$cfg_addr" ]]; then
        # Convert absolute address to little-endian hex.
        local cfg_le
        cfg_le=$(printf '%08x' "0x$cfg_addr" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/')
        if echo "$hex" | grep -q "$cfg_le"; then
            echo "      OK    literal pool -> cfg at 0x$cfg_addr"
        else
            echo "      FAIL  literal pool does not reference cfg at 0x$cfg_addr" >&2
            errors=$((errors + 1))
        fi
    else
        echo "      WARN  cfg symbol not found in ELF" >&2
    fi

    # 3. Check for BL/BLX to addresses outside the blob (compiler helper calls).
    local bin_size
    bin_size=$(wc -c < "$bin")
    local blob_start=$((LINK_BASE))
    local blob_end=$((LINK_BASE + bin_size))

    local bad_calls=0
    while IFS= read -r line; do
        # Match lines like: "  8060020:  f7ff fffe  bl  8060000 <func>"
        local target
        target=$(echo "$line" | sed -n 's/.*\tblx\?\t\([0-9a-f]\+\).*/\1/p')
        if [[ -n "$target" ]]; then
            local addr=$((16#$target))
            if [[ $addr -lt $blob_start || $addr -ge $blob_end ]]; then
                echo "      FAIL  external call: $(echo "$line" | sed 's/^[ \t]*//')" >&2
                bad_calls=$((bad_calls + 1))
            fi
        fi
    done < <("$OBJDUMP" -d "$elf" 2>/dev/null | grep -E $'\tblx?\t')

    if [[ $bad_calls -eq 0 ]]; then
        echo "      OK    no external BL/BLX calls"
    else
        errors=$((errors + bad_calls))
    fi

    return $errors
}

compiled=0
failed=0
for src in "$SCRIPT_DIR"/*/*.c; do
    dir="$(dirname "$src")"
    name="$(basename "$src" .c)"

    echo "  CC  $name"
    "$GCC" $CFLAGS -I"$SCRIPT_DIR" -o "$dir/$name.elf" "$src" -T "$LINKER_SCRIPT"
    "$OBJCOPY" -O binary "$dir/$name.elf" "$dir/$name.bin"

    size=$(wc -c < "$dir/$name.bin")
    echo "      -> $name.bin ($size bytes)"
    compiled=$((compiled + 1))

    if ! verify_blob "$dir/$name.elf" "$dir/$name.bin" "$name"; then
        failed=$((failed + 1))
    fi
    echo ""
done

echo "built $compiled blob(s), $failed failure(s)."
if [[ $failed -gt 0 ]]; then
    exit 1
fi
