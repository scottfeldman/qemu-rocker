/*
 * QEMU rocker switch emulation - front-panel ports
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "net/clients.h"

#include "rocker_fp.h"

/*
 * A nic is created for the front panel port and is peered
 * with a netdev with the id=port->name.  The port netdev
 * can be created from cmd line using:
 *
 *     -netdev <type>,id=<port_name>
 *
 * example:
 *
 *     -netdev tap,id=sw1.1
 *
 * Alternative, rocker can automatically create the netdevs
 * for all ports using cmd line:
 *
 *     -device rocker,name=<switch_name>,backend=<type>
 *
 * example:
 *
 *     -device rocker,name=sw1,backend=tap,fp_ports=4
 *
 * Would create 4 host tap interfaces with names sw1.[1-4].
 * The rocker nics would be peered with each netdev.
 */

#if defined (DEBUG_ROCKER)
#  define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "ROCKER: " fmt, ## __VA_ARGS__); } while (0)
#else
static inline GCC_FMT_ATTR(1, 2) int DPRINTF(const char *fmt, ...)
{
    return 0;
}
#endif

struct fp_port {
    struct rocker *rocker;
    uint index;
    char *name;
    bool enabled;
    enum fp_port_backend backend;
    enum fp_port_mode mode;
    NICState *nic;
    NICConf conf;
    fp_port_ig *ig;
};

static int fp_port_ig_drop(struct fp_port *port, const struct iovec *iov,
                           int iovcnt)
{
    /* silently drop ingress pkt */
    return iov_size(iov, iovcnt);
}

static int fp_port_can_receive(NetClientState *nc)
{
    return 0;
}

static ssize_t fp_port_receive_iov(NetClientState *nc, const struct iovec *iov,
                                   int iovcnt)
{
    struct fp_port *port = qemu_get_nic_opaque(nc);

    if (!port->enabled)
        return iov_size(iov, iovcnt);

    if (port->ig)
        return port->ig(port, iov, iovcnt);

    DPRINTF("Port receive handler not set; dropping packet\n");
    return iov_size(iov, iovcnt);
}

static ssize_t fp_port_receive(NetClientState *nc, const uint8_t *buf,
                               size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return fp_port_receive_iov(nc, &iov, 1);
}

static void fp_port_cleanup(NetClientState *nc)
{
}

static void fp_port_set_link_status(NetClientState *nc)
{
}

static NetClientInfo fp_port_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = fp_port_can_receive,
    .receive = fp_port_receive,
    .receive_iov = fp_port_receive_iov,
    .cleanup = fp_port_cleanup,
    .link_status_changed = fp_port_set_link_status,
};

void fp_port_set_conf(struct fp_port *port, char *sw_name,
                      MACAddr *start_mac, struct rocker *r,
                      uint index)
{
    port->rocker = r;
    port->index = index;

    /* front-panel switch port names are 1-based */
    port->name = g_strdup_printf("%s.%d", sw_name, index + 1);

    memcpy(port->conf.macaddr.a, start_mac, sizeof(port->conf.macaddr.a));
    port->conf.macaddr.a[5] += index;
    port->conf.bootindex = -1;
}

void fp_port_clear_conf(struct fp_port *port)
{
    g_free(port->name);
}

static int fp_port_set_tap_netdev(struct fp_port *port, char *script,
                                  char *downscript)
{
    NetdevTapOptions nctap = {
        .has_ifname = true,
        .ifname = port->name,
        .has_script = script ? true : false,
        .script = script,
        .has_downscript = downscript ? true : false,
        .downscript = downscript,
    };
    struct NetClientOptions ncopts = {
        .kind = NET_CLIENT_OPTIONS_KIND_TAP,
        .tap = &nctap,
    };

    return net_init_tap(&ncopts, port->name, NULL);
}

int fp_port_set_netdev(struct fp_port *port,
                       enum fp_port_backend backend,
                       char *script, char *downscript)
{
    port->backend = backend;

    switch (backend) {
    case FP_BACKEND_NONE:
        return 0;
    case FP_BACKEND_TAP:
        return fp_port_set_tap_netdev(port, script, downscript);
    default:
        DPRINTF("Invalid backend mode %d\n", backend);
        return -1;
    }
}

void fp_port_clear_netdev(struct fp_port *port)
{
}

int fp_port_set_nic(struct fp_port *port, const char *type)
{
    /* find the netdev to peer with, if any, by matching
     * id=port->name
     */

    port->conf.peers.ncs[0] = qemu_find_netdev(port->name);

    port->nic = qemu_new_nic(&fp_port_info, &port->conf,
                             type, NULL, port);
    qemu_format_nic_info_str(qemu_get_queue(port->nic),
                             port->conf.macaddr.a);

    return 0;
}

void fp_port_clear_nic(struct fp_port *port)
{
    qemu_del_nic(port->nic);
    port->nic = NULL;
}

void fp_port_set_mode(struct fp_port *port, enum fp_port_mode mode,
                      fp_port_ig *ig)
{
    switch (mode) {
    case FP_MODE_UNASSIGNED:
    case FP_MODE_FLOW:
    case FP_MODE_L2_L3:
        port->mode = mode;
        port->ig = ig;
        if (!ig)
            DPRINTF("WARNING port mode set (%d) but no ingress handler installed\n",
                    mode);
        break;
    default:
        DPRINTF("Invalid port mode %d\n", mode);
    }
}

void fp_port_enable(struct fp_port *port)
{
    port->enabled = true;
}

void fp_port_disable(struct fp_port *port)
{
    port->enabled = false;
}

struct fp_port *fp_port_alloc(void)
{
    struct fp_port *port = g_malloc0(sizeof(struct fp_port));

    if (port)
        fp_port_set_mode(port, FP_MODE_UNASSIGNED, fp_port_ig_drop);

    return port;
}

void fp_port_free(struct fp_port *port)
{
    g_free(port);
}
