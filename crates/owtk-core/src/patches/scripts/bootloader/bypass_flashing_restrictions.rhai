fn patch() {
    #{
        id: "bypass_flashing_restrictions",
        name: "Bypass Flashing Restrictions",
        description: "Bypasses the RSA signature check and new firmware version comparison the bootloader performs to make sure the existing and/or ota firmware has not been tampered with and is newer than what is installed.",
        boards: #{
            "GT": [
                #{ versions: [3], targets: [
                    #{ offset: 0x38F8, original: "10 B5 EE B0", meta: #{ patched: "01 20 70 47" } },
                    #{ offset: 0x2D23, original: "D2", meta: #{ patched: "E0" } },
                ]},
            ],
            "GTS": [
                #{ versions: [4], targets: [
                    #{ offset: 0x3914, original: "10 B5 EE B0", meta: #{ patched: "01 20 70 47" } },
                    #{ offset: 0x2D39, original: "D2", meta: #{ patched: "E0" } },
                ]},
            ],
            "XRC": [
                #{ versions: [5], targets: [
                    #{ offset: 0x2D44, original: "10 B5 EE B0", meta: #{ patched: "01 20 70 47" } },
                    #{ offset: 0x3925, original: "D2", meta: #{ patched: "E0" } },
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
