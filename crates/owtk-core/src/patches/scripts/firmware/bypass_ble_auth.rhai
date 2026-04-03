fn patch() {
    #{
        id: "bypass_ble_auth",
        name: "Bypass BLE Authentication",
        description: "Bypasses the BLE authentication check for use with apps that don't have proper authentication.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0x6AA6, original: "60 7C 00 28 00 F0 8D 83", meta: #{ patched: "01 20 60 74 36 E0 00 BF" } },
                ]},
                #{ versions: [4165], targets: [
                    #{ offset: 0x65B8, original: "01 78 00 29 1D D0", meta: #{ patched: "01 21 01 70 1E E0" } },
                ]},
            ],
            "Pint": [
                #{ versions: [5040], targets: [
                    #{ offset: 0x6A9A, original: "60 7C 00 28 00 F0 4B 83", meta: #{ patched: "01 20 60 74 37 E0 00 BF" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0x386, original: "01 78 00 29 24 D0", meta: #{ patched: "01 21 01 70 25 E0" } },
                ]},
                #{ versions: [5205, 5207], targets: [
                    #{ offset: 0x396, original: "01 78 00 29 24 D0", meta: #{ patched: "01 21 01 70 25 E0" } },
                ]},
            ],
            "PintX": [
                #{ versions: [5076], targets: [
                    #{ offset: 0x659A, original: "60 7C 00 28 1D D0", meta: #{ patched: "01 20 60 74 1E E0" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0x386, original: "01 78 00 29 24 D0", meta: #{ patched: "01 21 01 70 25 E0" } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0x396, original: "01 78 00 29 24 D0", meta: #{ patched: "01 21 01 70 25 E0" } },
                ]},
            ],
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x38A, original: "60 7C 00 28 00 F0 F6 83", meta: #{ patched: "01 20 60 74 3A E0 00 BF" } },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x716, original: "01 78 00 29 00 F0 24 84", meta: #{ patched: "01 21 01 70 40 E0 00 BF" } },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x712, original: "01 78 00 29 00 F0 E2 83", meta: #{ patched: "01 21 01 70 3F E0 00 BF" } },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x716, original: "01 78 00 29 00 F0 24 84", meta: #{ patched: "01 21 01 70 40 E0 00 BF" } },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x716, original: "01 78 00 29 00 F0 24 84", meta: #{ patched: "01 21 01 70 40 E0 00 BF" } },
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
