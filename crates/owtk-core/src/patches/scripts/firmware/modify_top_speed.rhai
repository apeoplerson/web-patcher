fn patch() {
    #{
        id: "modify_top_speed",
        name: "Modify Top Speed",
        description: "Modifies the top speed for ride modes.\nDue to firmware optimizations, not all ride modes will be separately configurable.",
        boards: #{
            "XR": [
                #{ versions: [4142], targets: [
                    #{ offset: 0x7818, original: "40 F2 87 30", meta: #{ rd: 0, mode: "Sequoia" } },
                    #{ offset: 0x78AC, original: "40 F2 33 40", meta: #{ rd: 0, mode: "Cruz" } },
                    #{ offset: 0x7946, original: "40 F2 35 56", meta: #{ rd: 6, mode: "Mission/Elevated/Custom" } },
                    #{ offset: 0x7AA2, original: "40 F2 35 50", meta: #{ rd: 0, mode: "Delirium" } },
                ]},
                #{ versions: [4165], targets: [
                    #{ offset: 0x700C, original: "40 F2 87 30", meta: #{ rd: 0, mode: "Sequoia" } },
                    #{ offset: 0x706E, original: "40 F2 33 45", meta: #{ rd: 5, mode: "Cruz" } },
                    #{ offset: 0x70F6, original: "40 F2 35 5E", meta: #{ rd: 14, mode: "Mission/Elevated/Custom" } },
                    #{ offset: 0x7240, original: "40 F2 35 55", meta: #{ rd: 5, mode: "Delirium" } },
                ]},
            ],
            "Pint": [
                #{ versions: [5040], targets: [
                    #{ offset: 0x7828, original: "40 F2 DD 30", meta: #{ rd: 0, mode: "Redwood" } },
                    #{ offset: 0x78C2, original: "40 F2 0A 56", meta: #{ rd: 6, mode: "Pacific/Elevated/Custom" } },
                    #{ offset: 0x7A1C, original: "40 F2 0A 50", meta: #{ rd: 0, mode: "Skyline" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0xD78, original: "40 F2 DD 31", meta: #{ rd: 1, mode: "Redwood" } },
                    #{ offset: 0xDEC, original: "40 F2 0A 51", meta: #{ rd: 1, mode: "Pacific/Elevated/Custom" } },
                    #{ offset: 0xE54, original: "40 F2 0A 51", meta: #{ rd: 1, mode: "Skyline" } },
                ]},
                #{ versions: [5205, 5207], targets: [
                    #{ offset: 0xC82, original: "40 F2 DD 31", meta: #{ rd: 1, mode: "Redwood" } },
                    #{ offset: 0xD7E, original: "40 F2 0A 51", meta: #{ rd: 1, mode: "Pacific/Elevated/Skyline/Custom" } },
                ]},
            ],
            "PintX": [
                #{ versions: [5076], targets: [
                    #{ offset: 0x7044, original: "40 F2 DD 34", meta: #{ rd: 4, mode: "Redwood" } },
                    #{ offset: 0x70D6, original: "40 F2 B6 5A", meta: #{ rd: 10, mode: "Pacific/Elevated/Custom" } },
                    #{ offset: 0x7218, original: "40 F2 B6 5A", meta: #{ rd: 10, mode: "Skyline" } },
                ]},
                #{ versions: [5100], targets: [
                    #{ offset: 0xD78, original: "40 F2 DD 31", meta: #{ rd: 1, mode: "Redwood" } },
                    #{ offset: 0xDEC, original: "40 F2 B6 51", meta: #{ rd: 1, mode: "Pacific/Elevated/Custom" } },
                    #{ offset: 0xE54, original: "40 F2 B6 51", meta: #{ rd: 1, mode: "Skyline" } },
                ]},
                #{ versions: [5200], targets: [
                    #{ offset: 0xCC0, original: "40 F2 DD 35", meta: #{ rd: 5, boost: 172, mode: "Redwood" } },
                    #{ offset: 0xD34, original: "40 F2 B6 57", meta: #{ rd: 7, boost: 172, mode: "Pacific/Elevated/Custom" } },
                    #{ offset: 0xE40, original: "40 F2 B6 55", meta: #{ rd: 5, boost: 172, mode: "Skyline" } },
                ]},
            ],
            "GT": [
                #{ versions: [6109], targets: [
                    #{ offset: 0x1332, original: "40 F2 06 30", meta: #{ rd: 0, mode: "Bay" } },
                    #{ offset: 0x13A2, original: "4F F4 AC 60", meta: #{ rd: 0, mode: "Roam" } },
                    #{ offset: 0x1414, original: "4F F4 D7 61", meta: #{ rd: 1, mode: "Flow" } },
                    #{ offset: 0x14C2, original: "4F F4 D7 63", meta: #{ rd: 3, mode: "Highline/Elevated/Custom" } },
                    #{ offset: 0x1600, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Apex" } },
                ]},
                #{ versions: [6210], targets: [
                    #{ offset: 0x1756, original: "40 F2 06 30", meta: #{ rd: 0, mode: "Bay" } },
                    #{ offset: 0x17CC, original: "4F F4 AC 60", meta: #{ rd: 0, mode: "Roam" } },
                    #{ offset: 0x1844, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Flow" } },
                    #{ offset: 0x18EC, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Highline/Elevated/Custom" } },
                    #{ offset: 0x194E, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Apex" } },
                ]},
            ],
            "GTS": [
                #{ versions: [6167], targets: [
                    #{ offset: 0x1686, original: "40 F2 06 30", meta: #{ rd: 0, mode: "Bay" } },
                    #{ offset: 0x1700, original: "4F F4 AC 60", meta: #{ rd: 0, mode: "Roam" } },
                    #{ offset: 0x177C, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Flow" } },
                    #{ offset: 0x1828, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Highline/Elevated/Custom" } },
                    #{ offset: 0x188A, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Apex" } },
                ]},
                #{ versions: [6208], targets: [
                    #{ offset: 0x1752, original: "40 F2 06 30", meta: #{ rd: 0, mode: "Bay" } },
                    #{ offset: 0x17BE, original: "4F F4 AC 60", meta: #{ rd: 0, mode: "Roam" } },
                    #{ offset: 0x182C, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Flow" } },
                    #{ offset: 0x18CA, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Highline/Elevated/Custom" } },
                    #{ offset: 0x1922, original: "40 F6 66 00", meta: #{ rd: 0, mode: "Apex" } },
                ]},
            ],
            "XRC": [
                #{ versions: [6213], targets: [
                    #{ offset: 0x1756, original: "40 F2 06 30", meta: #{ rd: 0, mode: "Sequoia" } },
                    #{ offset: 0x17CC, original: "4F F4 AC 60", meta: #{ rd: 0, mode: "Cruz" } },
                    #{ offset: 0x1844, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Mission" } },
                    #{ offset: 0x18EC, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Session/Elevated/Custom" } },
                    #{ offset: 0x194E, original: "4F F4 D7 60", meta: #{ rd: 0, mode: "Delirium" } },
                ]},
            ],
        }
    }
}

fn parameters() {
    TARGETS.map(|t| #{
        name: t.meta["mode"],
        label: t.meta["mode"],
        kind: "int",
        min: 500,
        max: 3000,
    })
}

fn apply(params) {
    TARGETS.map(|t| {
        let boost = if "boost" in t.meta { t.meta["boost"] } else { 0 };
        #{
            offset: t.offset,
            bytes: thumb_movw(t.meta["rd"], params[t.meta["mode"]] - boost)
        }
    })
}

fn read(fw) {
    let result = #{};
    for t in TARGETS {
        let current = fw[t.offset.to_string()];
        // Auto-detect encoding: MOVW (T3) has hw1 high byte 0xF2/0xF6,
        // MOV.W (T2) has 0xF0/0xF4. This handles both stock and patched bytes.
        let value = if (current[1] & 0xFB) == 0xF2 {
            decode_thumb_movw(current)
        } else {
            decode_thumb_mov_w(current)
        };
        let boost = if "boost" in t.meta { t.meta["boost"] } else { 0 };
        result[t.meta["mode"]] = value + boost;
    }
    result
}
