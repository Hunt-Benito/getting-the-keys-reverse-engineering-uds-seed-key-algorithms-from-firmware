# TECU-3 training firmware build.
#
# Any arm-none-eabi GCC works (apt install gcc-arm-none-eabi, or an xPack
# release). Produces tecu3_fw.bin: raw flash image at 0x08000000, padded
# to 4K with 0xFF like an erased-flash read.

CROSS   ?= arm-none-eabi-
CC      := $(CROSS)gcc
OBJCOPY := $(CROSS)objcopy
OBJDUMP := $(CROSS)objdump
SIZE    := $(CROSS)size

CFLAGS  := -mcpu=cortex-m3 -mthumb -Os -g -ffreestanding -fno-builtin \
           -Wall -Wextra -Werror -ffunction-sections -fdata-sections
LDFLAGS := -mcpu=cortex-m3 -mthumb -nostdlib -T linker.ld \
           -Wl,--gc-sections -Wl,-Map=tecu3_fw.map

SRC := src/startup.c src/main.c src/tecu_security.c
OBJ := $(SRC:.c=.o)

all: tecu3_fw.bin

tecu3_fw.elf: $(OBJ) linker.ld
	$(CC) $(LDFLAGS) $(OBJ) -o $@
	$(SIZE) $@

tecu3_fw.bin: tecu3_fw.elf
	$(OBJCOPY) -O binary -R .bss -R .data --gap-fill=0xFF --pad-to=0x08001000 $< $@

tecu3_fw.lst: tecu3_fw.elf
	$(OBJDUMP) -d $< > $@

clean:
	rm -f $(OBJ) tecu3_fw.elf tecu3_fw.bin tecu3_fw.map tecu3_fw.lst

.PHONY: all clean
