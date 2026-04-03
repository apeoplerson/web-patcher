fn patch() {
    #{
        id: "spoof_generation",
        name: "Spoof Board Generation",
        description: "Changes what hardware revision the board returns, only affects third party apps.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0x6E02, original: "07 78 DF F8 58 09 04 2F 10 DB", meta: #{ template: "00 27 DF F8 58 09 00 BF 00 BF", value_offset: 0 } },
                    #{ offset: 0x6A30, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
                #{ versions: [4165], targets: [
                    #{ offset: 0x64BE, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                    #{ offset: 0x6830, original: "05 78 DF F8 D8 0A 04 2D 10 DB", meta: #{ template: "00 25 DF F8 D8 0A 00 BF 00 BF", value_offset: 0 } },
                ]},
            ],
            "Pint": [
                #{ versions: [5040], targets: [
                    #{ offset: 0x6A2C, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0x99A, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
                #{ versions: [5205, 5207], targets: [
                    #{ offset: 0x9B0, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
            ],
            "PintX": [
                #{ versions: [5076], targets: [
                    #{ offset: 0x64B2, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                    #{ offset: 0x6806, original: "05 78 DF F8 DC 0A 04 2D 10 DB", meta: #{ template: "00 25 DF F8 DC 0A 00 BF 00 BF", value_offset: 0 } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0x99A, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0x9CC, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
            ],
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x308, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                    #{ offset: 0x64A, original: "1F 78 41 78 02 78 04 2F 0E DB", meta: #{ template: "00 27 41 78 02 78 00 BF 00 BF", value_offset: 0 } },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x686, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                    #{ offset: 0xA8E, original: "09 78", meta: #{ template: "00 21", value_offset: 0 } },
                ]},
            ],
        }
    }
}

fn parameters() {
    [#{
        name: "generation",
        label: "Generation",
        description: "The hardware generation to report to third party apps.",
        kind: "enum",
        options: [
            #{ value: "4", label: "XR" },
            #{ value: "5", label: "Pint" },
            #{ value: "6", label: "GT" },
            #{ value: "7", label: "PintX/S" },
            #{ value: "8", label: "GTS" },
            #{ value: "9", label: "XRC" },
        ],
        initial: "4",
    }]
}

fn read(fw) {
    let t = TARGETS[0];
    let current = fw[t.offset.to_string()];
    let vo = t.meta["value_offset"];
    let value = decode_u8(current.extract(vo, 1));
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
