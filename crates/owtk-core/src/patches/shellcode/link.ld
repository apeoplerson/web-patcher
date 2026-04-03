/* Shared linker script for shellcode blobs.
 *
 * Link base is chosen above any real firmware region.  The patcher
 * relocates the single literal-pool reference to &cfg by replacing
 * (LINK_BASE + cfg_offset) with (runtime_addr + cfg_offset).
 *
 * Entry is always the first function in .entry — the patcher calls
 * offset 0, so an explicit ENTRY symbol is not required. */
LINK_BASE = 0x08060000;

SECTIONS {
    . = LINK_BASE;
    .text : {
        KEEP(*(.entry))
        *(.text*)
        *(.rodata*)

        /* Config struct — single block, patched by byte offset */
        KEEP(*(.cfg))
    }
    /DISCARD/ : {
        *(.ARM.attributes)
        *(.ARM.exidx*)
        *(.comment)
        *(.data)
        *(.bss)
    }
}
