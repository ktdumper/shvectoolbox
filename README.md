# shvec toolbox

A toolbox for exploring the srec bootloader exploit on SH-Mobile.

## Usage

First, run the `locate_commdesc` module like so:

```
sudo python exploit.py --vid 06d3 --pid 21b0 --addr 0x64000000 locate_commdesc
```

Make note of the output, e.g.

```
commdesc=0x6460xxxx
usb_interrupt=0x6460xxxx
```

Reconnect the device between executions.

Next, you can run `dump_memory` in order to readout memory from the device:

```
sudo python exploit.py --vid 06d3 --pid 21b0 --addr 0x64000000 --commdesc 0x6460xxxx --dump_addr 0xADDR --dump_size 0xSIZE dump_memory
```

## setup_exploit

For G1 phones. Example:

```
python setup_exploit.py --vid 04c5 --pid 1199 --smash 0x8ec --dump_addr 0xe0600000 --dump_size 0x40000
```

## g1_takeover

For G1 phones. Example:

```
# Most common
python g1_takeover.py --vid 04dd --pid 916f --addr 0xe0000000 --reboot 0xe0601938 --usb_reset 0xe0603318 --usb_getch 0xe0602c9c --usb_send 0xe0602f58 --usb_send_commit 0xe06029f0
# F884ies
python g1_takeover.py --vid 04c5 --pid 1199 --addr 0xe0000000 --reboot 0xe0601968 --usb_reset 0xe06032ec --usb_getch 0xe0602ccc --usb_send 0xe0602f88 --usb_send_commit 0xe0602a20
```

## Examples

### F902i

```
python exploit.py --vid 04c5 --pid 10ce --addr 0xE0000000 --commdesc 0xE04806F0 --dump_addr 0x30000000 --dump_size 0x400000 dump_memory
```

### F884i

```
sudo python exploit.py --vid 04c5 --pid 112a --addr 0x64000000 locate_commdesc
sudo python exploit.py --vid 04c5 --pid 112a --addr 0x64000000 --commdesc 0x64608354 --dump_addr 0x64600000 --dump_size 0x100000 dump_memory
```
