fn patch() {
    #{
        id: "disable_battery_type_check",
        name: "Disable Battery Type Check",
        description: "Disables the BMS battery type check that can cause error 16.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0xBBEC, original: "02 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xBBFA, original: "05 2A", meta: #{ patched: "92 42" } },
                ]},
                #{ versions: [4165], targets: [
                    #{ offset: 0xBE06, original: "02 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xBE0E, original: "04 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xBE1A, original: "05 29", meta: #{ patched: "89 42" } },
                ]},
            ],
            "Pint": [
                #{ versions: [5040], targets: [
                    #{ offset: 0xBCD4, original: "02 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xBCE2, original: "05 2A", meta: #{ patched: "92 42" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0xB940, original: "02 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xB954, original: "05 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xB962, original: "0A 29", meta: #{ patched: "89 42" } },
                ]},
                #{ versions: [5205], targets: [
                    #{ offset: 0xB362, original: "02 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB376, original: "05 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB384, original: "0A 2A", meta: #{ patched: "92 42" } },
                ]},
                #{ versions: [5207], targets: [
                    #{ offset: 0xB372, original: "02 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB386, original: "05 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB394, original: "0A 2A", meta: #{ patched: "92 42" } },
                ]},
            ],
            "PintX": [
                #{ versions: [5076], targets: [
                    #{ offset: 0xBB4A, original: "02 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xBB5E, original: "05 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xBB6C, original: "0A 29", meta: #{ patched: "89 42" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0xB940, original: "02 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xB954, original: "05 29", meta: #{ patched: "89 42" } },
                    #{ offset: 0xB962, original: "0A 29", meta: #{ patched: "89 42" } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0xB5C6, original: "02 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB5DA, original: "05 2A", meta: #{ patched: "92 42" } },
                    #{ offset: 0xB5E8, original: "0A 2A", meta: #{ patched: "92 42" } },
                ]},
            ],
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x11260, original: "09 28", meta: #{ patched: "80 42" } },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x14E34, original: "09 28", meta: #{ patched: "80 42" } },
                ]},
            ],
        }
    }
}

fn parameters() {
    []
}

fn apply(params) {
    TARGETS.map(|t| #{
        offset: t.offset,
        bytes: hex_to_blob(t.meta["patched"])
    })
}
