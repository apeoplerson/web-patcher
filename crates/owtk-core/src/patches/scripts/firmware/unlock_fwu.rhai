fn patch() {
    #{
        id: "unlock_fwu",
        name: "Unlock Firmware Update Mode",
        description: "Unlocks the Firmware Update Mode that normally requires normal and/or FCX authentication.",
        boards: #{
            "XR": [
                #{ versions: [4165], targets: [
                    #{ offset: 0xB990, original: "03 D1", meta: #{ patched: "00 BF" } },
                ]},
            ],
            "Pint": [
                #{ versions: [5100], targets: [
                    #{ offset: 0xBD3A, original: "6B D1", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xBD42, original: "67 D5", meta: #{ patched: "00 BF" } },
                ]},
                #{ versions: [5205], targets: [
                    #{ offset: 0xB784, original: "6F D1", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB78C, original: "6B D5", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB794, original: "67 D1", meta: #{ patched: "00 BF" } },
                ]},
                #{ versions: [5207], targets: [
                    #{ offset: 0xB794, original: "6F D1", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB79C, original: "6B D5", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB7A4, original: "67 D1", meta: #{ patched: "00 BF" } },
                ]},
            ],
            "PintX": [
                #{ versions: [5100], targets: [
                    #{ offset: 0xBD3A, original: "6B D1", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xBD42, original: "67 D5", meta: #{ patched: "00 BF" } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0xB9E8, original: "6F D1", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB9F0, original: "6B D5", meta: #{ patched: "00 BF" } },
                    #{ offset: 0xB9F8, original: "67 D1", meta: #{ patched: "00 BF" } },
                ]},
            ],
            "GT": [
                #{ versions: [6210], targets: [
                    #{ offset: 0x154F4, original: "40 F0 97 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x154FE, original: "40 F1 92 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x15508, original: "40 F0 8D 80", meta: #{ patched: "AF F3 00 80" } },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x13D50, original: "40 F0 92 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x13D5A, original: "40 F1 8D 80", meta: #{ patched: "AF F3 00 80" } },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x14974, original: "40 F0 97 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x1497E, original: "40 F1 92 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x14988, original: "40 F0 8D 80", meta: #{ patched: "AF F3 00 80" } },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x1535C, original: "40 F0 97 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x15366, original: "40 F1 92 80", meta: #{ patched: "AF F3 00 80" } },
                    #{ offset: 0x15370, original: "40 F0 8D 80", meta: #{ patched: "AF F3 00 80" } },
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
