# S5L8442Pwnage2

***Important note**: although this code is unlikely to permanently break anything, you still should be very careful. I'm not responsible for any possible damage this might cause*

Implementation of Pwnage 2.0 exploit for S5L8442 SoC which is used in iPod shuffle 3. It allows you to:

* Dump arbitrary memory
* Decrypt Image1-wrapped firmwares
    * ...as well as decrypt/encrypt arbitrary data with embedded GID key
* Boot custom 2nd-stage images

I only tested this on a M4 Max MacBook Pro, but given that it doesn't use any special USB haxx, it should run anywhere

For more info about Pwnage 2.0 itself, there is a good [article](https://freemyipod.org/wiki/Pwnage_2.0) on freemyipod wiki (the only thing I'd correct is that SecureROMs are not vulnerable to this bug because they are based on entirely different code)

## How to run
### Prerequisites

* iPod shuffle 3
    * Firmware [image](https://secure-appldnld.apple.com/iPod/SBML/osx/bundles/061-6315.20090526.AQS4R/iPod_132.1.1.ipsw) and ability to restore it
        * Finder in modern macOS can do it, even though it's very buggy

* Python 3
    * `pyusb` is the only external dependency
        * Available from **pip**

### Entering DFU on iPod shuffle 3

As you could notice, there is not a single button on that device, only 3-position switch

The only way to enter DFU is flashing a firmware with broken 2nd-stage bootloader:

1. Download the IPSW linked above
2. Unzip it
3. Open `D98.Bootloader.rb3` in a hex-editor and replace a random byte or 2 somewhere in a middle of the file
4. ZIP it back and rename file extension to `.ipsw`
5. Flash the resulting file into your iPod with Finder
6. At some point it will fail or get stuck
7. Unplug the iPod

As soon as Finder/iTunes detects an iPod in DFU mode, it will try to download a recovery image and upload **WTF** from it

We want to avoid it - you can either send SIGSTOP signal to `AMP*` processes on your Mac, or just temporarily disable Internet connection (so it cannot download the recovery image)

You know you did everything right if you see this on USB:

```
USB DFU Device:

  Product ID:	0x1224
  Vendor ID:	0x05ac (Apple Inc.)
  Version:	0.01
  Serial Number:	84420000000000ɧ
  Speed:	Up to 480 Mb/s
  Manufacturer:	Apple, Inc.
  Location ID:	0x00100000 / 1
  Current Available (mA):	500
  Current Required (mA):	100
  Extra Operating Current (mA):	0
```

Garbage in the end of serial number string is there by default, because they overwrite the end of it by some pointer (?!)

### If your iPod ever gets completely stuck

There is a reset combination:

1. Unplug your iPod from Mac
2. Turn the switch to the OFF position
3. Wait 10 seconds
4. Turn the switch to any other position
5. Plug it back to your Mac and restore

### Running the exploit

When your iPod is in DFU mode, just run the following:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 pwn                                                                           
DONE
```

You know it reached pwned DFU mode if you see this on USB:

```
S5L8442 pwnDFU:

  Product ID:	0x1224
  Vendor ID:	0x05ac (Apple Inc.)
  Version:	0.01
  Serial Number:	8442000000000001
  Speed:	Up to 480 Mb/s
  Manufacturer:	Apple, Inc.
  Location ID:	0x00100000 /#!/usr/bin/env python3

import time
import struct
import argparse
from contextlib import suppress
import usb

APPLE_VID = 0x5AC
S5L8442_USBDFU_PID = 0x1224

DNLD_MAX_PACKET_SIZE = 0x800
UPLD_MAX_PACKET_SIZE = 0x40

USB_TIMEOUT = 500

DEFAULT_PWN_IMAGE = "pwn.dfu"
EXPECTED_USB_NAME = "S5L8442 pwnDFU"

COMMAND_RESET  = 0x72657374   # 'rest'
COMMAND_DUMP   = 0x64756D70   # 'dump'
COMMAND_AESDEC = 0x61657364   # 'aesd'
COMMAND_AESENC = 0x61657365   # 'aese'

AES_BLOCK_SIZE = 16
AES_KEY_GID = 1
AES_KEY_UID = 2

class USBDFUDeviceError(Exception):
    pass

class USBDFUDevice:
    def __init__(self, pid: int, vid: int = APPLE_VID):
        self.pid = pid
        self.vid = vid

        self._dev = None
        self._open = False

    def open(self, attempts: int = 5):
        for _ in range(attempts):
            try:
                self._dev = usb.core.find(idProduct=self.pid, idVendor=self.vid)
                assert self._dev
                self._open = True
                break
            except Exception:
                time.sleep(0.25)

        if not self._open:
            raise USBDFUDeviceError("cannot open USB device - is it even connected?")

        self._dev.set_configuration(1)
        self._dev.set_interface_altsetting(0, 0)

    def close(self):
        usb.util.dispose_resources(self._dev)

    def usb_reset(self):
        with suppress(usb.core.USBError):
            self._dev.reset()

    def send_data(self, data: bytes) -> int:
        index = 0
        packets = 0
        while index < len(data):
            amount = min(len(data) - index, DNLD_MAX_PACKET_SIZE)
            assert (
                self._dev.ctrl_transfer(0x21, 1, packets, 0, data[index : index + amount], USB_TIMEOUT)
                == amount
            )

            result = (0, 0, 0, 0, 0, 0)
            while result[4] != 0x05:
                result = self._dev.ctrl_transfer(0xA1, 3, 0, 0, 6, USB_TIMEOUT)

            packets += 1
            index += amount

        return packets

    def get_data(self, amount: int = UPLD_MAX_PACKET_SIZE) -> bytes:
        return self._dev.ctrl_transfer(0xA1, 2, 0, 0, amount, USB_TIMEOUT)

    def clear_state(self):
        self._dev.ctrl_transfer(0x21, 4, 0, 0, "", USB_TIMEOUT)

    def request_image_validation(self, packets: int):
        assert self._dev.ctrl_transfer(0x21, 1, packets + 1, 0, "", USB_TIMEOUT) == 0
        try:
            for _ in range(3):
                self._dev.ctrl_transfer(0xA1, 3, 0, 0, 6, USB_TIMEOUT)
        except usb.core.USBError:
            pass

        self.usb_reset()

    def name(self):
        return usb.util.get_string(self._dev, 2, 0)

    def __del__(self):
        if self._open:
            self.close()
            self._open = False

class Image1:
    DATA_START_MAP = {
        "8900" : 0x800,
        "8442" : 0x800
    }

    def __init__(self, buffer: bytes):
        self.magic = buffer[:4].decode("ascii")
        self.version = buffer[4:7].decode("ascii")
        self.type = struct.unpack("<B", buffer[7:8])[0]

        self.dataoff = self.DATA_START_MAP[self.magic]

        (self.entrypoint, self.bodylen, self.datalen, self.certoff, self.certlen) = struct.unpack("<5I", buffer[8:28])

    def __repr__(self) -> str:
        return "Image1 v%s (%s): type: 0x%x entry: 0x%x bodylen: 0x%x datalen: 0x%x certoff: 0x%x certlen: 0x%x" % \
            (
                self.version,
                self.magic,
                self.type,
                self.entrypoint,
                self.bodylen,
                self.datalen,
                self.certoff,
                self.certlen
            )

def device_open() -> USBDFUDevice:
    dev = USBDFUDevice(S5L8442_USBDFU_PID)
    dev.open()

    name = dev.name()

    if name != EXPECTED_USB_NAME:
        print("unexpected USB device name, did you run the exploit?")
        exit(-1)

    return dev

def cmd_encode(command: int, *args) -> bytes:
    buf = struct.pack("<I", command)
    for arg in args:
        buf += struct.pack("<I", arg)

    return buf

def cmd_send(device: USBDFUDevice, cmd: bytes, length: int = UPLD_MAX_PACKET_SIZE) -> bytes:
    device.clear_state()
    device.send_data(cmd)
    device.clear_state()
    return device.get_data(length)

def aes_op(device: USBDFUDevice, cmd: int, key: int, buffer: bytes) -> bytes:
    total_len = len(buffer)

    if total_len % AES_BLOCK_SIZE:
        raise ValueError("AES operations require 16-byte aligned input")

    index = 0
    iv = bytes(16)
    ret = bytes()

    while True:
        op = "decrypting" if cmd == COMMAND_AESDEC else "encrypting"
        print("\r%s: %d%%" % (op, int(index / total_len * 100)), end="")

        if index >= total_len:
            break

        amount = min(total_len - index, UPLD_MAX_PACKET_SIZE)

        cmd_ser = cmd_encode(cmd, amount, key)
        cmd_ser += iv
        cmd_ser += buffer[index : index + amount]

        tmp = cmd_send(device, cmd_ser, amount)

        if cmd == COMMAND_AESDEC:
            iv = cmd_ser[-AES_BLOCK_SIZE:]
        else:
            iv = tmp[-AES_BLOCK_SIZE:]

        ret += tmp
        index += amount

    print()

    return ret

def do_pwn(args):
    dev = USBDFUDevice(S5L8442_USBDFU_PID)
    dev.open()

    if dev.name() == EXPECTED_USB_NAME:
        print("device is already pwned")
        exit(0)

    with open(args.override if args.override else DEFAULT_PWN_IMAGE, "rb") as f:
        buf = f.read()

    dev.request_image_validation(dev.send_data(buf))
    dev.close()

    dev = USBDFUDevice(S5L8442_USBDFU_PID)
    dev.open()

    name = dev.name()

    if name != EXPECTED_USB_NAME:
        print("unexpected USB device name after sending exploit - %s" % name)
        exit(-1)

    dev.close()

def do_dump(args):
    dev = device_open()

    f = open(args.file, "wb")

    index = 0
    while True:
        print("\rdumping: %d%%" % int(index / args.length * 100), end="")

        if index >= args.length:
            break

        amount = min(args.length - index, UPLD_MAX_PACKET_SIZE)

        f.write(
            cmd_send(
                dev,
                cmd_encode(
                    COMMAND_DUMP,
                    args.address + index,
                    amount
                ),
                amount
            )
        )

        index += amount

    print()

    f.close()
    dev.close()

def do_aes(args):
    dev = device_open()

    if args.op == "dec":
        cmd = COMMAND_AESDEC
    elif args.op == "enc":
        cmd = COMMAND_AESENC
    else:
        print("unknown operation - %s" % args.op)
        exit(-1)

    if args.key == "GID":
        key = AES_KEY_GID
    elif args.key == "UID":
        key = AES_KEY_UID
    else:
        print("unknown key - %s" % args.key)
        exit(-1)

    with open(args.input, "rb") as f:
        in_buf = f.read()

    with open(args.output, "wb") as f:
        f.write(aes_op(dev, cmd, key, in_buf))

    dev.close()

def do_image1(args):
    dev = device_open()

    with open(args.input, "rb") as f:
        in_buf = f.read()

    image1 = Image1(in_buf)

    print(image1)

    real_len = image1.bodylen
    padded_len = real_len

    if real_len % AES_BLOCK_SIZE:
        padded_len += AES_BLOCK_SIZE - (real_len % AES_BLOCK_SIZE)

    with open(args.output, "wb") as f:
        f.write(
            aes_op(
                dev,
                COMMAND_AESDEC,
                AES_KEY_GID,
                in_buf[image1.dataoff : image1.dataoff + padded_len]
            )[:real_len]
        )

    dev.close()

def do_reboot(args):
    dev = device_open()

    try:
        cmd_send(dev, cmd_encode(COMMAND_RESET))
    except Exception:
        pass

    dev.usb_reset()
    dev.close()

def do_boot(args):
    dev = device_open()

    with open(args.file, "rb") as f:
        in_buf = f.read()

    dev.clear_state()
    dev.send_data(in_buf)
    dev.clear_state()

    try:
        dev.get_data()
    except Exception:
        pass

    dev.close()

def hexint(str) -> int:
    return int(str, 16)

def main():
    parser = argparse.ArgumentParser(description="S5L8442 Pwnage2")
    subparsers = parser.add_subparsers()

    pwn_parse = subparsers.add_parser("pwn", help="run the exploit to enter pwnDFU mode")
    pwn_parse.set_defaults(func=do_pwn)
    pwn_parse.add_argument("-o", "--override", help="overrides DFU image for pwning", required=False)

    dump_parse = subparsers.add_parser("dump", help="dump some memory")
    dump_parse.set_defaults(func=do_dump)
    dump_parse.add_argument("file", help="file path to save to")
    dump_parse.add_argument("address", type=hexint)
    dump_parse.add_argument("length", type=hexint)

    aes_parse = subparsers.add_parser("aes", help="decrypt/encrypt with GID/UID key")
    aes_parse.set_defaults(func=do_aes)
    aes_parse.add_argument("op", help="operation - dec/enc")
    aes_parse.add_argument("key", help="key - GID/UID")
    aes_parse.add_argument("input", help="input file")
    aes_parse.add_argument("output", help="output file")

    image1_parse = subparsers.add_parser("image1", help="decrypt Image1")
    image1_parse.set_defaults(func=do_image1)
    image1_parse.add_argument("input", help="input file")
    image1_parse.add_argument("output", help="output file")

    boot_parse = subparsers.add_parser("boot", help="boot WTF from file")
    boot_parse.set_defaults(func=do_boot)
    boot_parse.add_argument("file", help="raw WTF to boot")

    reboot_parse = subparsers.add_parser("reboot", help="reboot device")
    reboot_parse.set_defaults(func=do_reboot)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        exit(-1)

    args.func(args)

    print("DONE")

if __name__ == "__main__":
    main() 2
  Current Available (mA):	500
  Current Required (mA):	100
  Extra Operating Current (mA):	0
```

Device name is changed to `S5L8442 pwnDFU` and serial number string is fixed

### Sample operations

Dumping ROM:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 dump /tmp/rom.bin 0x20000000 0x10000
dumping: 100%
DONE
```

Dumping SRAM:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 dump /tmp/sram.bin 0x62000000 0x80000
dumping: 100%
DONE
```

Decrypting Image1:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 image1 D98.Bootloader.rb3 /tmp/d98_boot.bin
Image1 v1.0 (8442): type: 0x3 entry: 0x0 bodylen: 0x18824 datalen: 0x19493 certoff: 0x188b0 certlen: 0xbe3
decrypting: 100%
DONE
```

Rebooting back into normal DFU:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 reboot                                                                           
DONE
```

Booting a 2nd-stage bootloader:

```
➜  S5L8442Pwnage2 git:(master) ✗ ./S5L8442Pwnage2 boot /tmp/d98_boot.bin
DONE
```

## Running your own code

Initial payload source code as well as DFU upload callback source code are available in this repository

You can modify them and recompile (requires ARM GNU toolchain)

Running makefile should yield a new `pwn.dfu` file. By default, `S5L8442Pwnage2 pwn` will use just that, but you can override what file it sends with `-o` option

`template.dfu` is here for you to run arbitrary payloads - just put your code at offset 0x800 (16 KiBs max) and send it to your iPod

## Precautions

* iPod shuffle 3 gets pretty hot after staying in DFU mode for a while, so do not leave it connected when you don't use it

* The exploit should also work for untethered boot as well, but you shouldn't try it, because in case of any seemingly minor problem - for instance, your custom bootloader entered an infinite loop - iPod might be unrecoverable!
    * You won't be able to enter DFU mode anymore, unless you find a "force DFU" test point on the MLB (if it even exists)

## Known issues

* Apparently padding in AES operations isn't handled properly, so for inputs not aligned to 16 bytes (AES block size) it might yield some garbage in the end of an output
    * This doesn't seem to cause many problems though, as all possible inputs are raw code images which always end with a lot of zeroes anyway

## Fun facts

* The CPU core is very cursed - none of the firmwares (ROM, WTF, bootloader, disk mode, OSOS) ever access CP15 registers, and running MCR/MRC instructions via the exploit seems to cause an exception
    * This means there is no MMU at all!
    * It also makes it very complex to understand what core this even is - `MIDR` register is also in CP15

* Even though iPod shuffle 3 was released in 2009, the S5L8442 ROM looks more similar to S5L8900 & S5L8702 ones (2007), than to S5L8730 (2009) or even S5L8720 (2008)

* SRAM is pretty large (512 KiB), but it seems that there's no DRAM, so it's the only memory available to software
    * Don't quote me on that though, as I didn't check it deeply

* Logging in post-ROM stages seems to be done via *semihosting*
    * Whenever it wants to print something, in essence it just does a certain supervisor call
    * External debugger traps it and fetches the string
    * If there's no external debugger, software handler just returns
    * Is there even normal UART?

* Firmwares don't seem to use EFI for anything unlike bigger non-iOS iPods

## Credits

* iPhone Dev Team - for the original Pwnage 2.0 bug & exploit
* q3k - for sharing a lot of research on iPod bootroms and helping me
