fn patch() {
    #{
        id: "change_bms_encryption_keys",
        name: "Change BMS Encryption Keys",
        description: "Lets the user change the BMS encryption key and nonce to, for example, use an XRC BMS with a GT controller.",
        boards: #{
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x12009, size: 32, blind: true, sha1: "6908ebc99c7963d8a467d35c1d7a852f12e9834b" },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x312, size: 32, blind: true, sha1: "6908ebc99c7963d8a467d35c1d7a852f12e9834b" },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x2F8, size: 32, blind: true, sha1: "07279efc0930f5f3bc4d8b27b3703bcc2fccb3dd" },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x30B, size: 32, blind: true, sha1: "07279efc0930f5f3bc4d8b27b3703bcc2fccb3dd" },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x314, size: 32, blind: true, sha1: "586b8a3c1bd7aba0f1fe8e175667785c026bdc7b" },
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
