#include <stdint.h>

#define PAYLOAD (%base%)

int main() {
    volatile uint8_t *once_ptr = (void*)(PAYLOAD + 0x20000);
    volatile uint8_t *args = (void*)(PAYLOAD + 0x10000);
    volatile uint8_t *commdesc = (void*)%commdesc%;

    uint8_t once = *once_ptr;
    if (once) {
        *once_ptr = 0;

        uint8_t *copysrc = (void*)(args[0] | (args[1] << 8) | (args[2] << 16) | (args[3] << 24));
        for (int i = 0; i < 16; ++i)
            commdesc[2 + i] = copysrc[i];

        commdesc[1] = once;
    }
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
