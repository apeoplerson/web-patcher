#include "../shellcode.h"

#define BSS_MAGIC 0xA5

struct __attribute__((packed)) config {
    uint32_t voltages_addr;
    uint32_t soc_addr;
    uint32_t drain_addr;
    uint32_t regen_addr;
    uint32_t bss_addr;
    uint32_t table_addr;
    uint16_t cell_count;
    uint16_t capacity_mah;
};

__attribute__((section(".cfg"), used))
volatile struct config cfg = {
    .voltages_addr = PH32(1),
    .soc_addr      = PH32(2),
    .drain_addr    = PH32(3),
    .regen_addr    = PH32(4),
    .bss_addr      = PH32(5),
    .table_addr    = PH32(6),
    .cell_count    = PH16(1),
    .capacity_mah  = PH16(2),
};

__attribute__((section(".entry"), used))
void soc_estimator(void) {
    volatile struct config *c = &cfg;

    volatile uint16_t *voltages = REG(volatile uint16_t *, c->voltages_addr);
    volatile uint8_t  *pct_out  = REG(volatile uint8_t  *, c->soc_addr);
    volatile int32_t  *drain    = REG(volatile int32_t  *, c->drain_addr);
    volatile int32_t  *regen    = REG(volatile int32_t  *, c->regen_addr);
    volatile uint8_t  *bss      = REG(volatile uint8_t  *, c->bss_addr);
    const    uint16_t *table    = REG(const    uint16_t *, c->table_addr);
    int cell_count              = c->cell_count;
    int capacity_mah            = c->capacity_mah;

    // Phase 1: Find minimum non-zero cell voltage.
    uint16_t min_v = 0xFFFF;
    for (int i = 0; i < cell_count; i++) {
        uint16_t v = voltages[i];
        if (v != 0 && v < min_v)
            min_v = v;
    }
    if (min_v == 0xFFFF)
        return;

    // Phase 2: Voltage-to-percentage lookup with interpolation.
    // Table: 11 entries, index 0 = 100%, index 10 = 0%, 10% steps.
    int voltage_pct = 0;
    for (int j = 0; j < 11; j++) {
        if (min_v >= table[j]) {
            if (j == 0) {
                voltage_pct = 100;
            } else {
                uint16_t upper = table[j - 1];
                uint16_t lower = table[j];
                voltage_pct = (10 - j) * 10 + 10 * (min_v - lower) / (upper - lower);
            }
            break;
        }
    }
    if (voltage_pct > 100) voltage_pct = 100;

    // Phase 3: Coulomb counting.
    int32_t current_net = *drain - *regen;

    // Phase 4: BSS state.
    // Force the compiler to materialize the BSS pointer in a register
    // instead of optimizing these accesses to stack locals.
    volatile uint8_t *bss_ptr = bss;
    __asm__ volatile("" : "+r"(bss_ptr) :: "memory");
    volatile int32_t *baseline_net_ptr = (volatile int32_t *)bss_ptr;
    volatile uint8_t *init_flag_ptr    = &bss_ptr[4];
    volatile uint8_t *baseline_pct_ptr = &bss_ptr[5];

    if (*init_flag_ptr == BSS_MAGIC) {
        int32_t delta = current_net - *baseline_net_ptr;
        int consumed_pct = (delta / 200) / capacity_mah;
        int coulomb_pct = *baseline_pct_ptr - consumed_pct;

        // Use coulomb estimate while it's reasonably close to the
        // voltage reading.  Only recalibrate when voltage drops well
        // below the estimate (battery sagging) or rises well above
        // it (significant charge recovered).
        int diff = voltage_pct - coulomb_pct;
        if (diff >= -2 && diff <= 5) {
            if (coulomb_pct > 100) coulomb_pct = 100;
            if (coulomb_pct < 1)   coulomb_pct = 1;
            *pct_out = (uint8_t)coulomb_pct;
            return;
        }
    }

    // Recalibrate.
    *init_flag_ptr    = BSS_MAGIC;
    *baseline_pct_ptr = (uint8_t)voltage_pct;
    *baseline_net_ptr = current_net;
    int pct = voltage_pct;
    if (pct > 100) pct = 100;
    if (pct < 1)   pct = 1;
    *pct_out = (uint8_t)pct;
}
