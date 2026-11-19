ENTRY(p3_entry)
PHDRS { guard PT_LOAD FLAGS(5); }
SECTIONS {
    . = 0;
    .guard : ALIGN(16) {
        KEEP(*(.text.p3_entry))
        *(.text .text.*)
        *(.rodata .rodata.*)
        . = ALIGN(16);
        KEEP(*(.p3config))
    } :guard
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.ARM.exidx*) }
}
