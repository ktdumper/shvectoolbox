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
