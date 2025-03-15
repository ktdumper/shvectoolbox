#include <inttypes.h>
#include <stddef.h>

#include "libc.h"
#include "libc.c"

__asm__(
    ".global dis_int\n"
    "dis_int:\n"
    ".word 0xe10f0000, 0xe1a01000, 0xe3811080, 0xe12ff001, 0xe1a0f00e\n"
);
void dis_int(void);

int (*usb_reset)() = (void*)%usb_reset%;
int (*usb_getch)() = (void*)%usb_getch%;
int (*usb_send)() = (void*)%usb_send%;
int (*usb_send_commit)() = (void*)%usb_send_commit%;

void send(void *buf, size_t sz) {
    usb_send(buf, sz);
    usb_send_commit();
}

void _putchar(char ch) {
    if (ch == '\n')
        _putchar('\r');
    send(&ch, 1);
    usb_getch();
}

uint8_t shellcode[0x2000] = { %shellcode% };

#define AP_STS ((*(volatile uint32_t*)0x50401ffc))
#define AP_CMD ((*(volatile uint32_t*)0x50401ff8))
#define AP_ARG ((*(volatile uint32_t*)0x50401ff0))
#define AP_ARGS (((volatile uint32_t*)0x50401ff0))

uint32_t ap_read32(uint32_t addr) {
    AP_STS = 0;
    AP_ARG = addr;
    AP_CMD = 1;
    while (1) {
        if (AP_STS)
            return AP_ARG;
    }
}

uint16_t ap_read16(uint32_t addr) {
    AP_STS = 0;
    AP_ARG = addr;
    AP_CMD = 2;
    while (1) {
        if (AP_STS)
            return AP_ARG;
    }
}

void ap_write8(uint8_t val, uint32_t addr) {
    AP_STS = 0;
    AP_ARGS[0] = addr;
    AP_ARGS[1] = val;
    AP_CMD = 3;
    while (1) {
        if (AP_STS)
            return;
    }
}

void start_ap(void) {
    volatile uint16_t *DAT_39060410 = (void*)0x39060410;
    volatile uint32_t *DAT_50401ff8 = (void*)0x50401ff8;
    volatile uint32_t *DAT_51000038 = (void*)0x51000038;
    volatile uint32_t *DAT_70000000 = (void*)0x70000000;
    volatile uint32_t *DAT_66180014 = (void*)0x66180014;
    volatile uint32_t *DAT_50800004 = (void*)0x50800004;
    volatile uint16_t *DAT_50800000 = (void*)0x50800000;

    AP_STS = 0;

    *DAT_39060410 &= 0xFFFE;
    *DAT_39060410 |= 2;
    while (1) {
        *DAT_50800004 = 0x80;
        if ((*DAT_50800004 & 0xC0) == 0)
            break;
        for (volatile int i = 0; i < 2000; ++i) {}
    }

    memcpy((void*)0x50400000, shellcode, sizeof(shellcode));

    *DAT_50401ff8 |= 0x101;

    do {
        *DAT_51000038 &= 0xffffff0f;
    } while ((*DAT_51000038 & 0xF0) != 0);

    *DAT_70000000 = 0xe0000000;

    *DAT_66180014 = *DAT_66180014 & 0xfff | 0xe6c20000;

    do {
        *DAT_51000038 &= 0xfffffbff;
    } while ((*DAT_51000038 & 0x400) != 0);

    *DAT_50800004 = 0x80;
    *DAT_50800000 &= 0xff3f;

    while (1) {
        if (AP_STS == 0xBBBAAA)
            break;
        for (volatile int i = 0; i < 1000; ++i) {}
    }
}

uint32_t nand_data_off;
uint32_t nand_addr_off;
uint32_t nand_cmd_off;

void probe_nand(uint32_t addr) {
    uint16_t addrbytes[8];

    ap_write8(0x90, addr + nand_cmd_off);
    ap_write8(0x00, addr + nand_addr_off);
    for (int i = 0; i < 8; ++i) {
        addrbytes[i] = ap_read16(addr + nand_data_off);
    }

    int found = 0;
    for (int i = 0; i < 8; ++i)
        if (addrbytes[i] != addrbytes[0])
            found = 1;

    if (found) {
        printf("0x%08X :: ", addr);
        for (int i = 0; i < 8; ++i)
            printf("0x%02X ", addrbytes[i]);
        printf("\n");
    }
}

void probe_onenand(uint32_t addr) {
    printf("0x%08X :: ", addr);

    uint16_t mid = ap_read16(addr + 2*0xF000);
    uint16_t did = ap_read16(addr + 2*0xF001);

    printf("0x%02X 0x%02X\n", mid, did);
}

uint8_t pagebuf[0x840];

void go(void) {
    printf("Enter secondary\n");

    uint32_t leak = *(volatile uint32_t*)0x7ffc;
    printf("leak: 0x%X\n", leak);

    printf("AP boot state before: 0x%X\n", *(uint8_t*)0xe040000a);

    printf("starting AP\n");
    start_ap();
    printf("AP boot state after: 0x%X\n", AP_STS);
    printf("done!\n");

    printf("Direct read\n");
    for (uint32_t addr = 0x01000000; addr < 0xA0000000; addr += 0x01000000) {
        if (ap_read32(addr) != 0xDEADDEAD)
            printf("0x%08X :: 0x%08X 0x%08X 0x%08X 0x%08X\n", addr, ap_read32(addr+0), ap_read32(addr+4), ap_read32(addr+8), ap_read32(addr+0xc));
    }
    printf("\n");

    printf("Probe OneNAND\n");
    for (uint32_t addr = 0x01000000; addr < 0xA0000000; addr += 0x01000000) {
        if (ap_read32(addr) != 0xDEADDEAD)
            probe_onenand(addr);
    }

    printf("Probe NAND\n");
    for (int shift = 1; shift <= 24; ++shift) {
        nand_data_off = 0 << shift;
        nand_addr_off = 1 << shift;
        nand_cmd_off = 2 << shift;
        printf("trying nand_data=+0x%X nand_addr=+0x%X nand_cmd=+0x%X\n", nand_data_off, nand_addr_off, nand_cmd_off);
        for (uint32_t addr = 0x01000000; addr < 0xA0000000; addr += 0x01000000) {
            if (ap_read32(addr) != 0xDEADDEAD)
                probe_nand(addr);
        }
        printf("\n");
    }
    printf("\n");

    while (1) {
        usb_getch();
    }
}

void main(void) {
    // dis_int();
    *(volatile uint16_t*)0x39060412 |= 8;
    for (volatile int i = 0; i < 1000000; ++i) {}
    usb_reset();
    for (volatile int i = 0; i < 100000; ++i) {}

    int ch = usb_getch();
    if (ch == 0xBB) {
        uint32_t handshake = 0xDDCCBBAA;
        send(&handshake, sizeof(handshake));
        go();
    }

    while (1) {}
}

__asm__(
".section .text.start\n"
".global start\n"
"start:\n"
    // clean data cache and flush icache before jumping to rest of payload
    // hopefully increase stability bc we only need 1-2 cache lines to hit
"    ldr r0, =%base%\n"
"    ldr r1, =%base%+0x10000\n"
"loop:\n"
"    mcr p15, 0, r0, c7, c10, 1\n"
"    add r0, r0, #32\n"
"    cmp r0, r1\n"
"    bne loop\n"
"    mov r0, #0\n"
"    mcr p15, 0, r0, c7, c5, 0\n"

"    b main\n"
);
