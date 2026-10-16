/* TECU-3 training firmware - flash at 0x08000000, 8K image. */

ENTRY(Reset_Handler)

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 8K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 8K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    .isr_vector : {
        KEEP(*(.isr_vector))
    } > FLASH

    .text : {
        *(.text*)
        KEEP(*(.init))
        KEEP(*(.fini))
        KEEP(*(.rodata*))
        . = ALIGN(4);
    } > FLASH

    /* security tables clustered in one place - find one, find them all */
    .secro : {
        . = ALIGN(16);
        KEEP(*(.secro))
        . = ALIGN(4);
    } > FLASH

    .data : {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss : {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    _sidata = LOADADDR(.data);

    /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.eh_frame*) }
}
