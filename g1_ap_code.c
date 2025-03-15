#include <inttypes.h>

#define AP_STS (*(volatile uint32_t*)0xe6c21ffc)
#define AP_CMD (*(volatile uint32_t*)0xe6c21ff8)
#define AP_ARG (*(volatile uint32_t*)0xe6c21ff0)
#define AP_ARGS ((volatile uint32_t*)0xe6c21ff0)

#define CMD_READ32 1
#define CMD_READ16 2
#define CMD_WRITE8 3

uint32_t saferead32(volatile uint32_t *ptr);
void safewrite8(uint8_t data, volatile uint8_t *ptr);

int main() {
    AP_CMD = 0;
    AP_STS = 0xBBBAAA;

    while (1) {
        uint32_t cmd = AP_CMD;
        switch (cmd) {
        case CMD_READ32: {
            AP_CMD = 0;
            volatile uint32_t *ptr = (void*)AP_ARG;
            AP_ARG = saferead32(ptr);
            AP_STS = 1;
            break;
        }
        case CMD_READ16: {
            AP_CMD = 0;
            volatile uint16_t *ptr = (void*)AP_ARG;
            AP_ARG = *ptr;
            AP_STS = 1;
            break;
        }
        case CMD_WRITE8: {
            AP_CMD = 0;
            volatile uint8_t *ptr = (volatile uint8_t*)(AP_ARGS[0]);
            uint8_t data = AP_ARGS[1];
            safewrite8(data, ptr);
            // *ptr = data;
            AP_STS = 1;
            break;
        }
        default:
            continue;
        }
    }
}

__asm__(
".section .text.start\n"
".global start\n"
"start:\n"
"b Reset\n"
"b UndefinedInstruction\n"
"b SoftwareInterrupt\n"
"b PrefetchAbort\n"
"b DataAbort\n"

"UndefinedInstruction:\n"
"SoftwareInterrupt:\n"
"PrefetchAbort:\n"
"infloop: b infloop\n"

"DataAbort:\n"
"ldr r0, =0xDEADDEAD\n"
"SUBS PC,R14,#4\n"

"Reset:\n"
"    ldr r0, =0xE6C21000\n"
"    mov sp, r0\n"
"    b main\n"
);

__asm__ (
".global saferead32\n"
"saferead32:\n"
"ldr r0, [r0]\n"
"nop\n"
"nop\n"
"nop\n"
"nop\n"
"bx lr\n"
".global safewrite8\n"
"safewrite8:\n"
"strb r0, [r1]\n"
"nop\n"
"nop\n"
"nop\n"
"nop\n"
"bx lr\n"
);
