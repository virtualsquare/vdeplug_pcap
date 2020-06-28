/*
 * libvdeplug - A library to connect to a VDE Switch.
 * Copyright (C) 2017 Renzo Davoli, University of Bologna
 * Some code taken from a previous project (vde_pcapplug) 
 *   (C) 2008 vy Luca Bigliardi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <libvdeplug.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include "libvdeplug_mod.h"
#include <pcap.h>

static VDECONN *vde_pcap_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args);
static ssize_t vde_pcap_recv(VDECONN *conn,void *buf,size_t len,int flags);
static ssize_t vde_pcap_send(VDECONN *conn,const void *buf,size_t len,int flags);
static int vde_pcap_datafd(VDECONN *conn);
static int vde_pcap_ctlfd(VDECONN *conn);
static int vde_pcap_close(VDECONN *conn);

struct vdeplug_module vdeplug_ops={
	.vde_open_real=vde_pcap_open,
	.vde_recv=vde_pcap_recv,
	.vde_send=vde_pcap_send,
	.vde_datafd=vde_pcap_datafd,
	.vde_ctlfd=vde_pcap_ctlfd,
	.vde_close=vde_pcap_close};

struct vde_pcap_conn {
	void *handle;
	struct vdeplug_module *module;
	pcap_t *pcap;
	int fddata;
	char errbuf[PCAP_ERRBUF_SIZE];
	char hwaddr[ETH_ALEN];
};

static void gethwaddr(const char *ifname, char *hwaddr) {
	int s;
	int ioctlok;
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) > 0) {
		ioctlok = ioctl(s, SIOCGIFHWADDR, &ifr);
		close(s);
	}
	if (s < 0 || ioctlok < 0)
		memset(hwaddr, 0, ETH_ALEN);
	else
		memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
}

static VDECONN *vde_pcap_open(char *given_vde_url, char *descr,int interface_version,
		struct vde_open_args *open_args)
{
	struct vde_pcap_conn *newconn;
	char *ifname = given_vde_url;
	if ((newconn=calloc(1,sizeof(struct vde_pcap_conn)))==NULL) {
		errno=ENOMEM;
		return NULL;
	}

	newconn->pcap = pcap_create(ifname, newconn->errbuf);
	if (newconn->pcap == NULL)
		goto abort;


	if (pcap_set_snaplen(newconn->pcap, VDE_ETHBUFSIZE) != 0)
		goto abort;
	if (pcap_set_promisc(newconn->pcap, 1) != 0)
		goto abort;
#if 0
	if (pcap_set_timeout(newconn->pcap, 1) != 0)
		goto abort;
#endif
	if (pcap_set_immediate_mode(newconn->pcap, 1) != 0)
		goto abort;
	if (pcap_activate(newconn->pcap) != 0)
		goto abort;
	if (pcap_setnonblock(newconn->pcap, 1, newconn->errbuf) != 0)
		goto abort;
	newconn->fddata=pcap_get_selectable_fd(newconn->pcap);

	if (pcap_datalink(newconn->pcap) != DLT_EN10MB ) {
		errno = EINVAL;
		goto abort;
	}

	gethwaddr(ifname, newconn->hwaddr);
	return (VDECONN *)newconn;
abort:
	if (newconn->pcap != NULL)
		pcap_close(newconn->pcap);
	free(newconn);
	return NULL;
}

static ssize_t vde_pcap_recv(VDECONN *conn,void *buf,size_t len,int flags)
{
	struct vde_pcap_conn *vde_conn = (struct vde_pcap_conn *)conn;
	const u_char *data;
	struct pcap_pkthdr hdr;
	if ((data = pcap_next(vde_conn->pcap, &hdr)) != NULL) {
		ssize_t minlen = (hdr.len <= len) ? hdr.len : len;
		struct ether_header *ethh = (void *) data;
		if (__builtin_expect(memcmp(ethh->ether_shost, vde_conn->hwaddr, ETH_ALEN) == 0, 0))
			return 1;
		else {
			memcpy(buf, data, minlen);
			return minlen;
		}
	} else
		return 1;
}

static ssize_t vde_pcap_send(VDECONN *conn,const void *buf,size_t len,int flags)
{
	struct vde_pcap_conn *vde_conn = (struct vde_pcap_conn *)conn;
	return pcap_inject(vde_conn->pcap, buf, len);
}

static int vde_pcap_datafd(VDECONN *conn)
{
	struct vde_pcap_conn *vde_conn = (struct vde_pcap_conn *)conn;
	return vde_conn->fddata;
}

static int vde_pcap_ctlfd(VDECONN *conn)
{
	return -1;
}

static int vde_pcap_close(VDECONN *conn)
{
	struct vde_pcap_conn *vde_conn = (struct vde_pcap_conn *)conn;
	pcap_close(vde_conn->pcap);
	free(vde_conn);
	return 0;
}
