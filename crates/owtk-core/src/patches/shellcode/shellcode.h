#pragma once
#include <stdint.h>

// Cast a config address field to a typed pointer.
#define REG(type, addr)   ((type)(uintptr_t)(addr))

// Cast a config address field to a Thumb function pointer.
#define THUMB(type, addr) ((type)(uintptr_t)((addr) | 1u))

// Unique placeholder values for config fields.  Each field gets a
// distinct magic value so the compiler can never merge or elide them.
// The patcher overwrites every field at apply time.
#define PH32(n) ((uint32_t)(0xDEAD0000u | (n)))
#define PH16(n) ((uint16_t)(0xBE00u | (n)))
