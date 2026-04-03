fn patch() {
    #{
        id: "disable_haptic",
        name: "Disable Haptic",
        description: "Disables speed and torque based haptic buzz.\nThe motor/error haptic is kept intact.",
        boards: #{
            "Pint": [
                #{ versions: [5100], targets: [
                    #{ offset: 0xA508, original: "42 D0", meta: #{ patched: "42 E0" } },
                ]},
                #{ versions: [5205], targets: [
                    #{ offset: 0x98E6, original: "44 D0", meta: #{ patched: "44 E0" } },
                ]},
                #{ versions: [5207], targets: [
                    #{ offset: 0x98EA, original: "44 D0", meta: #{ patched: "44 E0" } },
                ]},
            ],
            "PintX": [
                #{ versions: [5100], targets: [
                    #{ offset: 0xA508, original: "42 D0", meta: #{ patched: "42 E0" } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0x9B48, original: "44 D0", meta: #{ patched: "44 E0" } },
                ]},
            ],
            "GT": [
                #{ versions: [6210], targets: [
                    #{ offset: 0x13156, original: "47 D0", meta: #{ patched: "47 E0" } },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x11C32, original: "4A D0", meta: #{ patched: "4A E0" } },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x12616, original: "4A D0", meta: #{ patched: "4A E0" } },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x12FD0, original: "46 D0", meta: #{ patched: "46 E0" } },
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
