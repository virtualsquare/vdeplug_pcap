# VDEPLUG\_PCAP

*A pcap plugin for vdeplug4*

This libvdeplug module interconnects a client to an interface using the packet capture library
(pcap). All the data that is received by this plug is injected into interface and everything captured from that interface
is sent to the client.

Please notice that the pcap library captures and injects packets on the net, packets sent by the host are not captured,
injected packets are not received by the host.
So several clients using *libvdeplug\_pcap* on the same interface of the same host do not communicate among them (nor they communicate
with the host).

This module of libvdeplug4 can be used in any program supporting vde like
*vde\_plug*, *kvm*, *qemu*, *user-mode-linux*, *virtualbox*, *vdens*, programs using *vdestack*, etc.

## Install *vdeplug\_pcap*

*vdeplug\_pcap* uses cmake, so the standard procedure to build and install
this vdeplug plugin module is the following:

```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## EXAMPLE
```
vde_plug vde:// pcap://eth0
```
connects the standard vde\_switch to the interface eth0.

