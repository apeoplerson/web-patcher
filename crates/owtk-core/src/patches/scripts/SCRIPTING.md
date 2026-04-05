# Patch Script Authoring Guide

Each `.rhai` file in this directory is automatically picked up by the build
script, compiled at runtime, and registered in the patch registry.

Every patch is a **single Rhai script** that declares its metadata, UI
parameters, and produces the bytes to write into firmware.

---

## File Structure

Each `.rhai` file implements 2-4 functions:

```rhai
fn patch() {
    #{
        id: "my_patch",
        name: "My Patch",
        description: "A short description of what this patch does.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0xBBEC, original: "02 2A", meta: #{ patched: "92 42" } },
                ]},
            ],
        }
    }
}

fn parameters() { [] }

fn apply(params) {
    TARGETS.map(|t| #{
        offset: t.offset,
        bytes: hex_to_blob(t.meta["patched"])
    })
}
```

To add a new patch, drop a `.rhai` file into `src/patches/scripts/` and
rebuild — the build script picks it up automatically.

---

## Functions

### `patch()` — Required

Returns a map with patch metadata and target declarations:

| Field          | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `id`           | string | yes      | Machine-readable identifier, shared across firmware versions. |
| `name`         | string | yes      | Human-readable name shown in the UI. |
| `description`  | string | yes      | Longer description / tooltip. |
| `boards`       | map    | yes      | Board generation → version entries (see below). |
| `experimental` | bool   | no       | When `true` the UI shows a warning indicator. |
| `sram`         | map    | no       | SRAM allocation requests: `#{ label: size_bytes, ... }`. Addresses are assigned at apply time and available via the `SRAM` constant. |

#### Boards & Version Entries

The `boards` map maps board generation names to arrays of version entries:

```rhai
boards: #{
    "XR": [
        #{ versions: [4142], targets: [
            #{ offset: 0xBBEC, original: "02 2A", meta: #{ patched: "92 42" } },
        ]},
    ],
}
```

**Board Generation Names:** `XR`, `Pint`, `GT`, `PintX`, `PintS`, `GTS`, `XRC`
— must match the `BoardGeneration` enum in Rust.

**Version Entry:**

| Field      | Type       | Description |
|------------|------------|-------------|
| `versions` | `[int]`    | One or more firmware version numbers that share these offsets. |
| `targets`  | `[Target]` | Write targets with stock bytes and optional metadata. |

#### Target Types

**Fixed target** — overwrites bytes at a known offset with known stock bytes:

| Field      | Type   | Required | Description |
|------------|--------|----------|-------------|
| `offset`   | int    | yes      | Byte offset into decrypted firmware (hex literal like `0xBBEC`). |
| `original` | string | yes      | Expected stock firmware bytes as hex. Spaces allowed: `"02 2A"`. |
| `meta`     | map    | no       | Arbitrary data accessible to scripts as `TARGETS[i].meta["key"]`. |

**Blind target** — overwrites bytes at a known offset but the stock bytes
cannot be distributed (e.g. encryption keys). Detection and revert skip
these unless a `sha1` hash is provided:

| Field    | Type   | Required | Description |
|----------|--------|----------|-------------|
| `offset` | int    | yes      | Byte offset into decrypted firmware. |
| `size`   | int    | yes      | Number of bytes (replaces `original`). |
| `blind`  | bool   | yes      | Must be `true`. |
| `sha1`   | string | no       | SHA-1 hash (40 hex chars) of the stock bytes. Enables detection without distributing original bytes. |
| `meta`   | map    | no       | Arbitrary data accessible to scripts. |

```rhai
// Without hash — status will be "Blind" (cannot detect stock vs applied):
#{ offset: 0x12009, size: 32, blind: true }

// With hash — detection works (stock vs applied) without distributing bytes:
#{ offset: 0x12009, size: 32, blind: true, sha1: "6908ebc99c7963d8a467d35c1d7a852f12e9834b" }
```

**Append target** — dynamically allocated from the end of the firmware
image. The offset is assigned by the allocator before `apply()` runs:

| Field    | Type | Required | Description |
|----------|------|----------|-------------|
| `size`   | int  | yes      | Number of bytes to allocate. |
| `append` | bool | yes      | Must be `true`. |
| `meta`   | map  | no       | Arbitrary data accessible to scripts. |

```rhai
#{ append: true, size: 112, meta: #{ kind: "cave" } }
```

Appended allocations are reclaimed on subsequent patch operations via the
`OWTK_PAT` marker — they don't accumulate.

### `parameters()` — Required

Returns an array of parameter descriptors for the UI. Return `[]` for
toggle-like patches with no parameters.

The `TARGETS` constant is available in `parameters()`, so you can
generate controls dynamically based on target metadata — for example,
one integer slider per ride mode:

```rhai
fn parameters() {
    TARGETS.map(|t| #{
        name: t.meta["mode"],
        label: t.meta["mode"],
        description: `Top speed for ${t.meta["mode"]} mode.`,
        kind: "integer",
        min: 600,
        max: 3000,
        initial: t.meta["initial"],
    })
}
```

Static parameters work the same as before:

```rhai
fn parameters() {
    [#{
        name: "speed",
        label: "Speed (MPH)",
        description: "Maximum speed limit.",
        kind: "integer",
        min: 5,
        max: 30,
        initial: 15,
    }]
}
```

#### Parameter Kinds

| Kind      | Extra Fields            | Value Type |
|-----------|-------------------------|------------|
| `toggle`  | `initial` (bool)        | `Bool`     |
| `integer` | `min`, `max`, `initial` | `Int`      |
| `float`   | `min`, `max`, `initial` | `Float`    |
| `enum`    | `options`, `initial`    | `String`   |
| `hex`     | `len`                   | `Bytes`    |

Enum options are an array of `#{ value: "...", label: "..." }` maps.

Hex parameters render as a fixed-length hex string input. `len` is the
expected number of **bytes** (not hex characters).

> **Note:** `initial` is used instead of `default` because `default` is a
> reserved keyword in Rhai and would need to be quoted.

### `apply(params)` — Required

Takes a map of parameter name → value and returns an array of write
descriptors (`#{ offset, bytes }`). Each write must target a declared
offset with matching byte length.

The following constants are available:

| Name      | Type    | Description |
|-----------|---------|-------------|
| `TARGETS` | `Array` | Array of target maps (see below). |
| `SRAM`    | `Map`   | Map of SRAM label → allocated address (i64). Only present when the patch declares `sram` in `patch()`. |

```rhai
fn apply(params) {
    TARGETS.map(|t| #{
        offset: t.offset,
        bytes: hex_to_blob(t.meta["patched"])
    })
}
```

### `read(fw)` — Optional

Called when firmware is detected as Applied. Takes a map of offset (as
string key) → byte blob and returns a map of parameter name → current
value. Used to show actual applied values in the UI instead of defaults.

```rhai
fn read(fw) {
    let t = TARGETS[0];
    let current = fw[t.offset.to_string()];
    let value = decode_u8(current.extract(t.meta["value_offset"], 1));
    #{ "speed": value.to_string() }
}
```

If `read()` is not defined, defaults from `parameters()` are used.

---

## Detection

Detection is handled entirely in Rust — **no script involvement**:

- **Stock**: All checkable targets' bytes match their `original` values
  (or SHA-1 hash for blind targets with `sha1`).
- **Applied**: At least one checkable target's bytes differ.
- **Unknown**: A target offset extends past the firmware buffer.
- **Blind**: No targets could be checked (all blind without `sha1` + appends).

Blind targets **without** a `sha1` hash are skipped during detection.
Blind targets **with** a `sha1` hash participate in detection — the hash
of the firmware bytes is compared against the expected hash.

---

## TARGETS Constant

Each entry in the `TARGETS` array is a map with these fields:

| Field      | Type   | Description |
|------------|--------|-------------|
| `offset`   | int    | Byte offset (resolved for append targets). |
| `original` | Blob   | Stock bytes (zero-filled for blind/append targets). |
| `len`      | int    | Length of the target in bytes (`original.len()`). |
| `append`   | bool   | Whether this is a dynamically allocated target. |
| `blind`    | bool   | Whether the original bytes are unknown. |
| `sha1`     | Blob   | 20-byte SHA-1 hash of stock bytes (only present if declared). |
| `meta`     | Map    | Arbitrary metadata (only present if declared). |

---

## Script API

### Helper Functions

| Function                         | Description |
|----------------------------------|-------------|
| `hex_to_blob("02 2A")`          | Hex string → Blob. |
| `blob_write(dst, offset, src)`  | Write `src` bytes into `dst` at `offset`, return modified blob. |
| `blob_repeat(pattern, count)`   | Repeat a blob `count` times. |
| `bytes_equal(a, b)`             | Compare two blobs for equality. |
| `parse_int("42")`               | String → i64. |
| `pad_bytes(len, byte)`          | Generate `len` bytes all set to `byte`. |
| `nop_sled(byte_len)`            | Generate `byte_len` bytes of Thumb NOP instructions (`BF00`). Must be even. |
| `sha1(blob)`                    | Compute SHA-1 hash, returns 20-byte Blob. |
| `sha1_hex(blob)`                | Compute SHA-1 hash, returns 40-char lowercase hex string. |

### ARM Thumb-2 Helpers

| Function                         | Description |
|----------------------------------|-------------|
| `thumb_b(from, to)`             | Encode a Thumb unconditional branch (B, T2, ±2KB). Offsets are firmware byte addresses. |
| `thumb_b_w(from, to)`           | Encode a Thumb-2 wide branch (B.W, T4, ±16MB). |
| `thumb_bl(from, to)`            | Encode a Thumb-2 branch-with-link (BL, ±16MB). |
| `thumb_movw(rd, imm16)`         | Encode MOVW Rd, #imm16 (T3). Plain 16-bit immediate, 0–65535. |
| `thumb_movt(rd, imm16)`         | Encode MOVT Rd, #imm16 (T1). Writes imm16 into top half of Rd. |
| `thumb_mov_w(rd, imm)`          | Encode MOV.W Rd, #imm (T2, modified immediate). Returns empty blob if not encodable. |
| `decode_thumb_movw(blob)`       | Decode MOVW/MOVT → i64 immediate (extracts the 16-bit value). |
| `decode_thumb_mov_w(blob)`      | Decode MOV.W (T2) → i64 immediate (expands the modified immediate). |

### Encoding Functions

**Encoders** (value → Blob):
`encode_u8`, `encode_i8`, `encode_u16le`, `encode_u16be`, `encode_i16le`,
`encode_i16be`, `encode_u32le`, `encode_u32be`, `encode_i32le`, `encode_i32be`,
`encode_f32le`, `encode_f32be`, `encode_f64le`, `encode_f64be`

**Decoders** (Blob → value):
`decode_u8`, `decode_i8`, `decode_u16le`, `decode_u16be`, `decode_i16le`,
`decode_i16be`, `decode_u32le`, `decode_u32be`, `decode_i32le`, `decode_i32be`,
`decode_f32le`, `decode_f32be`, `decode_f64le`, `decode_f64be`

---

## Examples

### Toggle (no parameters)

```rhai
fn patch() {
    #{
        id: "disable_battery_type_check",
        name: "Disable Battery Type Check",
        description: "Disables the BMS battery type check.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0xBBEC, original: "02 2A", meta: #{ patched: "92 42" } },
                ]},
            ],
        }
    }
}

fn parameters() { [] }

fn apply(params) {
    TARGETS.map(|t| #{
        offset: t.offset,
        bytes: hex_to_blob(t.meta["patched"])
    })
}
```

### Enum with value readback

```rhai
fn patch() {
    #{
        id: "spoof_generation",
        name: "Spoof Board Generation",
        description: "Changes the reported hardware revision.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0x6EA2, original: "4F F4 7A 71 01 FB 07 01 89 B2",
                       meta: #{ template: "00 22 4F F4 7A 71 01 FB 02 01", value_offset: 0 } },
                ]},
            ],
        }
    }
}

fn parameters() {
    [#{
        name: "generation", label: "Generation",
        kind: "enum",
        options: [
            #{ value: "4", label: "XR" },
            #{ value: "5", label: "Pint" },
        ],
        initial: "4",
    }]
}

fn read(fw) {
    let t = TARGETS[0];
    let current = fw[t.offset.to_string()];
    let value = decode_u8(current.extract(t.meta["value_offset"], 1));
    #{ "generation": value.to_string() }
}

fn apply(params) {
    let value = parse_int(params["generation"]);
    TARGETS.map(|t| #{
        offset: t.offset,
        bytes: blob_write(
            hex_to_blob(t.meta["template"]),
            t.meta["value_offset"],
            encode_u8(value)
        )
    })
}
```

### Blind target with hex parameters

```rhai
fn patch() {
    #{
        id: "change_bms_encryption_keys",
        name: "Change BMS Encryption Keys",
        description: "Lets the user change the BMS encryption key and nonce.",
        boards: #{
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x12009, size: 32, blind: true,
                       sha1: "6908ebc99c7963d8a467d35c1d7a852f12e9834b" },
                ]},
            ],
        }
    }
}

fn parameters() {
    [#{
         name: "enc_key",
         label: "Key",
         description: "Encryption Key as hex.",
         kind: "hex",
         len: 16,
    }, #{
         name: "enc_nonce",
         label: "Nonce",
         description: "Encryption Nonce as hex.",
         kind: "hex",
         len: 16,
    }]
}

fn apply(params) {
    [#{
        offset: TARGETS[0].offset,
        bytes: params.enc_key + params.enc_nonce,
    }]
}

fn read(fw) {
    let data = fw[`${TARGETS[0].offset}`];
    #{
        enc_key: data.extract(0, 16),
        enc_nonce: data.extract(16, 16),
    }
}
```
