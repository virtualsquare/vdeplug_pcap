<!--
.\" Copyright (C) 2020 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

`libvdeplug_pcap` -- vdeplug module for vde_switch based networks

# SYNOPSIS
libvdeplug_pcap.so

# DESCRIPTION

This libvdeplug module interconnects a client to an interface using the packet capture library
(pcap): all the data that is received by this plug is injected into interface and everything captured from that interface
is sent to the client.

Please notice that the pcap library captures and injects packets on the net, packets sent by the host are not captured,
injected packets are not received by the host.
So several clients using libvdeplug_pcap on the same interface of the same host do not communicate among them (nor they 
communicate with the host).

This  module of libvdeplug4 can be used in any program supporting vde like
`vde_plug`, `vdens`, `kvm`, `qemu`, `user-mode-linux` and `virtualbox`.

The vde_plug_url syntax of this module is the following:

:  `pcap://`*interface_name*

# EXAMPLE

```
vde_plug vde:// pcap://eth0
```

connects the standard vde_switch to the interface eth0.

# NOTICE

Virtual  Distributed  Ethernet  is not related in any way with www.vde.com ("Verband der Elektrotechnik, Elektronik
und Informationstechnik" i.e. the German "Association for Electrical, Electronic & Information Technologies").

# SEE ALSO
`vde_plug`(1), `vdens`(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli

