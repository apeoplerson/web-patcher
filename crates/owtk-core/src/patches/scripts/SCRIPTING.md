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

| Field         | Type   | Required | Description |
|---------------|--------|----------|-------------|
| `id`          | string | yes      | Machine-readable identifier, shared across firmware versions. |
| `name`        | string | yes      | Human-readable name shown in the UI. |
| `description` | string | yes      | Longer description / tooltip. |
| `boards`      | map    | yes      | Board generation → version entries (see below). |

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

**Target:**

| Field      | Type     | Required | Description |
|------------|----------|----------|-------------|
| `offset`   | int      | yes      | Byte offset into decrypted firmware (hex literal like `0xBBEC`). |
| `original` | string   | yes      | Expected stock firmware bytes as hex. Spaces allowed: `"02 2A"`. |
| `meta`     | map      | no       | Arbitrary data accessible to scripts as `TARGETS[i].meta["key"]`. |

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

| Kind      | Extra Fields          | Value Type |
|-----------|-----------------------|------------|
| `toggle`  | `initial` (bool)      | `Bool`     |
| `integer` | `min`, `max`, `initial` | `Int`    |
| `float`   | `min`, `max`, `initial` | `Float`  |
| `enum`    | `options`, `initial`  | `String`   |

Enum options are an array of `#{ value: "...", label: "..." }` maps.

> **Note:** `initial` is used instead of `default` because `default` is a
> reserved keyword in Rhai and would need to be quoted.

### `apply(params)` — Required

Takes a map of parameter name → value and returns an array of write
descriptors (`#{ offset, bytes }`). Each write must target a declared
offset with matching byte length.

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

- **Stock**: All targets' bytes match their `original` values.
- **Applied**: At least one target's bytes differ from `original`.
- **Unknown**: A target offset extends past the firmware buffer.

---

## Script API

### Constants

| Name      | Type    | Description |
|-----------|---------|-------------|
| `TARGETS` | `Array` | Array of target maps with `offset`, `original`, `len`, and optional `meta`. |

### Helper Functions

| Function                         | Description |
|----------------------------------|-------------|
| `hex_to_blob("02 2A")`          | Hex string → Blob. |
| `blob_write(dst, offset, src)`  | Write `src` bytes into `dst` at `offset`, return modified blob. |
| `parse_int("42")`               | String → i64. |
| `bytes_equal(a, b)`             | Compare two blobs for equality. |

### ARM Thumb-2 Helpers

| Function                         | Description |
|----------------------------------|-------------|
| `nop_sled(byte_len)`            | Generate `byte_len` bytes of Thumb NOP instructions (`BF00`). Must be even. |
| `pad_bytes(len, byte)`          | Generate `len` bytes all set to `byte`. |
| `blob_repeat(pattern, count)`   | Repeat a blob `count` times. |
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
