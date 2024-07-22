#include <stdint.h>

#define SCAN_ITER (0x100000)

int main() {
    static uint32_t scan_start;

    if (!scan_start) {
        scan_start = *(uint32_t*)0x20;
        scan_start &= 0xFFFF0000;
    }

    for (uint8_t *addr = (uint8_t*)scan_start; addr < (uint8_t*)(scan_start + SCAN_ITER); ++addr) {
        // 12010002ffffff...
        if (addr[0] == 0x12 && addr[1] == 0x01 && addr[2] == 0x00 && addr[3] == 0x02 && addr[4] == 0xFF) {
            addr[1] = 0xDE;
            addr[2] = 0xAD;
            addr[3] = 0xBE;
            addr[4] = 0xEF;

            addr[5] = ((uint32_t)addr) & 0xFF;
            addr[6] = ((uint32_t)addr >> 8) & 0xFF;
            addr[7] = ((uint32_t)addr >> 16) & 0xFF;
            addr[8] = ((uint32_t)addr >> 24) & 0xFF;

            addr[9] = ((uint32_t)scan_start) & 0xFF;
            addr[10] = ((uint32_t)scan_start >> 8) & 0xFF;
            addr[11] = ((uint32_t)scan_start >> 16) & 0xFF;
            addr[12] = ((uint32_t)scan_start >> 24) & 0xFF;
            break;
        }
    }

    scan_start += SCAN_ITER;
}

__asm__(
".section .text.start\n"
".global start\n"
"start:\n"
    // prepare space for chainloaded PC
"    sub sp, #4\n"
"    stmdb sp!,{r0,r1,r2,r3,r4,r5,r12,lr}\n"

"    bl main\n"

    // chainload to the real usb interrupt
"    mov r0, #0x20\n"
"    ldr r0, [r0]\n"
"    str r0, [sp,#32]\n"

"    ldmia sp!,{r0,r1,r2,r3,r4,r5,r12,lr,pc}\n"
);
