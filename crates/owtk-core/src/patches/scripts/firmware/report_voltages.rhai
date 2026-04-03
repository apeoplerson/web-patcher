fn patch() {
    #{
        id: "report_voltages",
        name: "Report Voltages",
        description: "Enables reporting of individual cell voltages and pack voltage over BLE.",
        experimental: true,
        sram: #{ cell_id: 2 },
        boards: #{
            "XR": [
                #{ versions: [4165], targets: [
                    #{ offset: 0x65FC, original: "20 7C 04 28 27 D1", meta: #{ kind: "hook", continue_to: 0x6652 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x0800AF4A, battery_voltage_addr: 0x20001CD0, cell_voltages_addr: 0x20001B50 } },
                ]},
            ],
            "Pint": [
                #{ versions: [5100], targets: [
                    #{ offset: 0x3D8, original: "20 7D 04 28 2A D1", meta: #{ kind: "hook", continue_to: 0x434 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08004DBA, battery_voltage_addr: 0x200020DC, cell_voltages_addr: 0x20001F7C } },
                ]},
                #{ versions: [5205], targets: [
                    #{ offset: 0x3E8, original: "20 7D 04 28 28 D1", meta: #{ kind: "hook", continue_to: 0x440 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x0800503E, battery_voltage_addr: 0x20002130, cell_voltages_addr: 0x20001FAC } },
                ]},
                #{ versions: [5207], targets: [
                    #{ offset: 0x3E8, original: "20 7D 04 28 28 D1", meta: #{ kind: "hook", continue_to: 0x440 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x0800503E, battery_voltage_addr: 0x20002130, cell_voltages_addr: 0x20001FAC } },
                ]},
            ],
            "PintX": [
                #{ versions: [5076], targets: [
                    #{ offset: 0x65DE, original: "20 7C 04 28 27 D1", meta: #{ kind: "hook", continue_to: 0x6634 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x0800AF38, battery_voltage_addr: 0x20001CA6, cell_voltages_addr: 0x20001B38 } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0x3D8, original: "20 7D 04 28 2A D1", meta: #{ kind: "hook", continue_to: 0x434 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08004DBA, battery_voltage_addr: 0x200020DC, cell_voltages_addr: 0x20001F7C } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0x3E8, original: "20 7D 04 28 2A D1", meta: #{ kind: "hook", continue_to: 0x444 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08005195, battery_voltage_addr: 0x20002148, cell_voltages_addr: 0x20001FC4 } },
                ]},
            ],
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x406, original: "25 7C 04 2D 2E D1", meta: #{ kind: "hook", continue_to: 0x46A } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08022A6A, battery_voltage_addr: 0x20002B46, cell_voltages_addr: 0x20002988 } },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x79E, original: "25 7C 04 2D 2E D1", meta: #{ kind: "hook", continue_to: 0x802 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08023BAC, battery_voltage_addr: 0x20002EBC, cell_voltages_addr: 0x20002AF8 } },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x798, original: "25 7C 04 2D 2E D1", meta: #{ kind: "hook", continue_to: 0x7FC } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08023818, battery_voltage_addr: 0x20002E38, cell_voltages_addr: 0x20002AA4 } },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x79E, original: "25 7C 04 2D 2E D1", meta: #{ kind: "hook", continue_to: 0x802 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08023C40, battery_voltage_addr: 0x20002EAC, cell_voltages_addr: 0x20002AD4 } },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x79E, original: "25 7C 04 2D 2E D1", meta: #{ kind: "hook", continue_to: 0x802 } },
                    #{ append: true, size: 112, meta: #{ kind: "cave", set_char_addr: 0x08023BA8, battery_voltage_addr: 0x20002EBC, cell_voltages_addr: 0x20002B04 } },
                ]},
            ],
        }
    }
}

fn parameters() { [] }

fn apply(params) {
    // Report voltages — compiled from report_voltages.c with arm-none-eabi-gcc.
    // Linked at 0x08060000; single literal-pool entry at +0x58 holds the
    // link-time address of the config struct (0x0806005C = code+0x5C).
    // 88 bytes code + 24 bytes config = 112 bytes.
    //
    // Config struct at code+0x5C:
    //   +0x5C  u32  set_char_addr
    //   +0x60  u32  battery_voltage_addr
    //   +0x64  u32  cell_voltages_addr
    //   +0x68  u32  cell_id_addr (SRAM allocated)
    //   +0x6C  u16  cell_count
    //   +0x6E  u16  is_f4
    let cave_code = hex_to_blob("2de9f041144b1c685a689f68dd68b3f810805e8a118844f0010489b21520a0472b8801339bb2984598bf00232b8037f813200b2192b25eb1b2fbf1f1c1f30b0141ea033189b223461a20bde8f04118470a204243f0e700bf5c0006080100adde0200adde0300adde0400adde01be02be");
    let LINK_BASE = 0x08060000;
    let CFG_OFF = 0x5C;
    let POOL_OFF = 0x58;

    let cell_count = if BOARD_GEN == "GTS" { 27 } else if BOARD_GEN == "GT" || BOARD_GEN == "XRC" { 18 } else { 15 };
    let is_f4 = if BOARD_GEN == "GT" || BOARD_GEN == "GTS" || BOARD_GEN == "XRC" { 1 } else { 0 };

    let cave_offset = 0;
    let continue_to = 0;
    let fw_base = if BOARD_GEN == "GT" || BOARD_GEN == "GTS" || BOARD_GEN == "XRC" { 0x08020000 } else { 0x08003000 };
    for t in TARGETS {
        if t.meta["kind"] == "cave" { cave_offset = t.offset; }
        if t.meta["kind"] == "hook" { continue_to = t.meta["continue_to"]; }
    }
    let cave_addr = fw_base + cave_offset;

    TARGETS.map(|t| {
        let kind = t.meta["kind"];

        if kind == "hook" {
            let bl = thumb_bl(t.offset, cave_offset);
            let b = thumb_b(t.offset + 4, continue_to);
            #{ offset: t.offset, bytes: bl + b }

        } else {
            let code = cave_code;
            let m = t.meta;

            // Relocate the single literal-pool entry from link-time to runtime.
            code = blob_write(code, POOL_OFF, encode_u32le(cave_addr + CFG_OFF));

            // Patch config struct at code+0x5C.
            code = blob_write(code, CFG_OFF + 0x00, encode_u32le(m["set_char_addr"]));
            code = blob_write(code, CFG_OFF + 0x04, encode_u32le(m["battery_voltage_addr"]));
            code = blob_write(code, CFG_OFF + 0x08, encode_u32le(m["cell_voltages_addr"]));
            code = blob_write(code, CFG_OFF + 0x0C, encode_u32le(SRAM["cell_id"]));
            code = blob_write(code, CFG_OFF + 0x10, encode_u16le(cell_count));
            code = blob_write(code, CFG_OFF + 0x12, encode_u16le(is_f4));

            #{ offset: t.offset, bytes: code }
        }
    })
}
