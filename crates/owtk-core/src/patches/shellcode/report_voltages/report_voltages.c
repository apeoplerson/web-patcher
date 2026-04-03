#include "../shellcode.h"

typedef void (*set_char_fn)(uint8_t id, uint16_t value);

struct __attribute__((packed)) config {
    uint32_t set_char_addr;
    uint32_t bat_voltage_addr;
    uint32_t cell_voltages_addr;
    uint32_t cell_id_addr;
    uint16_t cell_count;
    uint16_t is_f4;
};

__attribute__((section(".cfg"), used))
volatile struct config cfg = {
    .set_char_addr       = PH32(1),
    .bat_voltage_addr    = PH32(2),
    .cell_voltages_addr  = PH32(3),
    .cell_id_addr        = PH32(4),
    .cell_count          = PH16(1),
    .is_f4               = PH16(2),
};

__attribute__((section(".entry"), used))
void report_voltages(void) {
    volatile struct config *c = &cfg;

    set_char_fn set_char      = THUMB(set_char_fn, c->set_char_addr);
    volatile uint16_t *bat_v  = REG(volatile uint16_t *, c->bat_voltage_addr);
    volatile uint16_t *cells  = REG(volatile uint16_t *, c->cell_voltages_addr);
    volatile uint16_t *id_ptr = REG(volatile uint16_t *, c->cell_id_addr);
    int cell_count            = c->cell_count;
    int is_f4                 = c->is_f4;

    // Report pack voltage (BtCom_BatteryVoltage = 0x15).
    set_char(0x15, *bat_v);

    // Report one cell voltage per call (BtCom_BatteryCells = 0x1A).
    // Cycles through cells via persistent counter.
    uint16_t cell_id = *id_ptr;
    cell_id++;
    if (cell_id >= cell_count)
        cell_id = 0;
    *id_ptr = cell_id;

    // BLE format: ((scaled_voltage) & 0xFFF) | (cell_id << 12)
    // F1: raw is millivolts, encode as 10*raw/11
    // F4: raw is mV*10, encode as raw/11 (skip the *10)
    uint32_t raw = cells[cell_id];
    uint32_t scaled;
    if (is_f4) {
        scaled = raw / 11;
    } else {
        scaled = (raw * 10) / 11;
    }
    uint16_t ble_value = (scaled & 0xFFF) | (cell_id << 12);
    set_char(0x1A, ble_value);
}
