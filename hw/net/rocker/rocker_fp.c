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

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_world.h"

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

enum duplex {
    DUPLEX_HALF = 0,
    DUPLEX_FULL
};

struct fp_port {
    struct rocker *r;
    struct world *world;
    uint index;
    char *name;
    uint16_t lport;
    bool enabled;
    uint32_t speed;
    uint8_t duplex;
    uint8_t autoneg;
    enum fp_port_backend backend;
    NICState *nic;
    NICConf conf;
    bool link_up;
};

bool fp_port_get_link_up(struct fp_port *port)
{
    return port->link_up;
}

void fp_port_get_macaddr(struct fp_port *port, MACAddr macaddr)
{
    memcpy(macaddr.a, port->conf.macaddr.a, sizeof(macaddr.a));
}

void fp_port_set_macaddr(struct fp_port *port, MACAddr macaddr)
{
//XXX    memcpy(port->conf.macaddr.a, macaddr.a, sizeof(port->conf.macaddr.a));
}

int fp_port_get_settings(struct fp_port *port, uint32_t *speed,
                         uint8_t *duplex, uint8_t *autoneg)
{
    *speed = port->speed;
    *duplex = port->duplex;
    *autoneg = port->autoneg;

    return 0;
}

int fp_port_set_settings(struct fp_port *port, uint32_t speed,
                         uint8_t duplex, uint8_t autoneg)
{
    // XXX validate inputs

    port->speed = speed;
    port->duplex = duplex;
    port->autoneg = autoneg;

    return 0;
}

bool fp_port_from_lport(uint16_t lport, uint16_t *port)
{
    if (lport < 1 || lport > ROCKER_FP_PORTS_MAX)
        return false;
    *port = lport - 1;
    return true;
}

int fp_port_eg(struct fp_port *port, const struct iovec *iov, int iovcnt)
{
    NetClientState *nc = qemu_get_queue(port->nic);

    if (port->enabled)
        qemu_sendv_packet(nc, iov, iovcnt);

    return 0;
}

static int fp_port_can_receive(NetClientState *nc)
{
    struct fp_port *port = qemu_get_nic_opaque(nc);

    return port->enabled;
}

static ssize_t fp_port_receive_iov(NetClientState *nc, const struct iovec *iov,
                                   int iovcnt)
{
    struct fp_port *port = qemu_get_nic_opaque(nc);

    return world_ingress(port->world, port->lport, iov, iovcnt);
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
    struct fp_port *port = qemu_get_nic_opaque(nc);
    struct rocker *r = port->r;

    if (port->link_up == !nc->link_down)
        return;

    port->link_up = !nc->link_down;
    rocker_irq_status_append(r, ROCKER_IRQ_LINK);
    rocker_update_irq(r);
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

void fp_port_set_conf(struct fp_port *port, struct rocker *r, char *sw_name,
                      MACAddr *start_mac, uint index)
{
    port->r = r;
    port->index = index;
    port->lport = index + 1;

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
        return -EINVAL;
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

struct world *fp_port_get_world(struct fp_port *port)
{
    return port->world;
}

void fp_port_set_world(struct fp_port *port, struct world *world)
{
    port->world = world;
}

bool fp_port_enabled(struct fp_port *port)
{
    return port->enabled;
}

void fp_port_enable(struct fp_port *port)
{
    port->enabled = true;
    DPRINTF("port %d enabled\n", port->index);
}

void fp_port_disable(struct fp_port *port)
{
    port->enabled = false;
    DPRINTF("port %d disabled\n", port->index);
}

struct fp_port *fp_port_alloc(void)
{
    struct fp_port *port = g_malloc0(sizeof(struct fp_port));

    if (!port)
        return NULL;
    fp_port_reset(port);

    return port;
}

void fp_port_free(struct fp_port *port)
{
    g_free(port);
}

void fp_port_reset(struct fp_port *port)
{
    fp_port_disable(port);
    port->speed = 10000;   /* 10Gbps */
    port->duplex = DUPLEX_FULL;
    port->autoneg = 0;
}
