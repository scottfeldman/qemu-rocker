/*
 * QEMU rocker switch emulation
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

#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "qemu/iov.h"

#include "rocker_hw.h"
#include "tlv_parse.h"

#define ROCKER "rocker"
#define ROCKER_FP_PORTS_MAX 62

enum backend_mode {
    BACKEND_NONE,
    BACKEND_TAP,
};

struct rocker {
    /* private */
    PCIDevice parent_obj;
    /* public */

    MemoryRegion mmio;
    enum backend_mode backend;

    /* switch configuration */
    char *name;                  /* switch name */
    char *backend_name;          /* backend method */
    char *script;                /* script to run for tap backends */
    char *downscript;            /* downscript to run for tap backends */
    uint16_t fp_ports;           /* front-panel port count */
    MACAddr fp_start_macaddr;    /* front-panel port 0 mac addr */

    /* each front-panel port is a qemu nic, with private configuration */
    struct fp_port {
        struct rocker *bp;
        NICState *state;
        NICConf conf;
    } fp_port[ROCKER_FP_PORTS_MAX];
};

#define to_rocker(obj) \
    OBJECT_CHECK(struct rocker, (obj), ROCKER)

static int rocker_can_receive(NetClientState *nc)
{
    return 0;
}

static ssize_t rocker_receive_iov(NetClientState *nc, const struct iovec *iov,
                                  int iovcnt)
{
    size_t size = iov_size(iov, iovcnt);

    return size;
}

static ssize_t rocker_receive(NetClientState *nc, const uint8_t *buf,
                              size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return rocker_receive_iov(nc, &iov, 1);
}

static void rocker_cleanup(NetClientState *nc)
{
}

static void rocker_set_link_status(NetClientState *nc)
{
}

static NetClientInfo net_rocker_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = rocker_can_receive,
    .receive = rocker_receive,
    .receive_iov = rocker_receive_iov,
    .cleanup = rocker_cleanup,
    .link_status_changed = rocker_set_link_status,
};

static void rocker_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                              unsigned size)
{
}

static uint64_t rocker_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}

static const MemoryRegionOps rocker_mmio_ops = {
    .read = rocker_mmio_read,
    .write = rocker_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void pci_rocker_uninit(PCIDevice *dev)
{
    struct rocker *r = to_rocker(dev);
    int i;

    for (i = 0; i < r->fp_ports; i++)
        qemu_del_nic(r->fp_port[i]);

    memory_region_destroy(&r->mmio);
}

static void rocker_set_fp_port_conf(struct rocker *r)
{
    const MACAddr zero = { .a = { 0,0,0,0,0,0 } };
    const MACAddr dflt = { .a = { 0x52, 0x54, 0x00, 0x12, 0x35, 0x01 } };
    static int index = 0;
    int i;

    if (memcmp(&r->fp_start_macaddr, &zero, sizeof(zero)) == 0) {
        memcpy(&r->fp_start_macaddr, &dflt, sizeof(dflt));
        r->fp_start_macaddr.a[4] += (index++);
    }

    for (i = 0; i < r->fp_ports; i++) {
        memcpy(&r->fp_port[i].conf.macaddr, &r->fp_start_macaddr,
               sizeof(r->fp_port[i].conf.macaddr));
        r->fp_port[i].conf.macaddr.a[5] += i;
        r->fp_port[i].conf.bootindex = -1;

        // TODO: for each fp_port, need to create backend linkage.
        // TODO: conf.peer needs to be set as if user typed:
        // TODO:    -net nic,netdev=<name>.<i>
        // TODO: then, the backend for each port needs to be
        // TODO: created.  FOr tap backend, for example, it
        // TODO: would be the equivalent to the user typing:
        // TODO:    -netdev tap,id=<name>.<i>,ifname=<name>.<i>,
        // TODO:            script=<script>,downscript=<downscript>

        // TODO: each fp_port would have a host tap interface.
        // TODO: the tap script can create a netns and put in
        // TODO: fp_port tap interface.  Now the fp_port is
        // TODO: isolated on the host from the other fp_ports,
        // TODO: and each netns is effectively a unqiue link
        // TODO: partner for the switch port.

        //r->fp_port[i].conf.peers = XXX; // XXX
    }
}

static int pci_rocker_init(PCIDevice *pci_dev)
{
    uint8_t *pci_conf = pci_dev->config;
    struct rocker *r = to_rocker(pci_dev);
    int i;

    pci_conf[PCI_INTERRUPT_PIN] = ROCKER_PCI_INTERRUPT_PIN;

    /* set up memory-mapped region at BAR0 */

    memory_region_init_io(&r->mmio, OBJECT(r), &rocker_mmio_ops, r,
                          "rocker-mmio", ROCKER_PCI_BAR0_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &r->mmio);

    /* validate switch properties */

    if (!r->name)
        r->name = g_strdup(ROCKER);

    if (!r->backend_name || memcmp(r->backend_name, "tap", sizeof("tap") == 0))
        r->backend = BACKEND_TAP;

    if (r->fp_ports > ROCKER_FP_PORTS_MAX)
        r->fp_ports = ROCKER_FP_PORTS_MAX;

    rocker_set_fp_port_conf(r);

    for (i = 0; i < r->fp_ports; i++) {
        r->fp_port[i] = qemu_new_nic(&net_rocker_info, &r->fp_port_conf[i],
                                     object_get_typename(OBJECT(r)), NULL, r);
        qemu_format_nic_info_str(qemu_get_queue(r->fp_port[i]),
                                 r->fp_port_conf[i].macaddr.a);
    }

    return 0;
}

static void rocker_reset(DeviceState *dev)
{
}

static Property rocker_properties[] = {
    DEFINE_PROP_STRING("name", struct rocker, name),
    DEFINE_PROP_STRING("backend", struct rocker, backend_name),
    DEFINE_PROP_STRING("script", struct rocker, script),
    DEFINE_PROP_STRING("downscript", struct rocker, downscript),
    DEFINE_PROP_UINT16("fp_ports", struct rocker,
                       fp_ports, 16),
    DEFINE_PROP_MACADDR("fp_start_macaddr", struct rocker,
                        fp_start_macaddr),
    DEFINE_PROP_END_OF_LIST(),
};

static void rocker_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_rocker_init;
    k->exit = pci_rocker_uninit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = PCI_DEVICE_ID_REDHAT_ROCKER;
    k->revision = ROCKER_PCI_REVISION;
    k->class_id = PCI_CLASS_NETWORK_OTHER;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Rocker Switch";
    dc->reset = rocker_reset;
    dc->props = rocker_properties;
}

static const TypeInfo rocker_info = {
    .name          = ROCKER,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(struct rocker),
    .class_init    = rocker_class_init,
};

static void rocker_register_types(void)
{
    type_register_static(&rocker_info);
}

type_init(rocker_register_types)
