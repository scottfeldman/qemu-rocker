/*
 * QEMU rocker switch emulation - PCI device
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

#include "rocker_hw.h"
#include "rocker_fp.h"
#include "tlv_parse.h"

#define ROCKER "rocker"
#define ROCKER_FP_PORTS_MAX 62

struct rocker {
    /* private */
    PCIDevice parent_obj;
    /* public */

    MemoryRegion mmio;

    /* switch configuration */
    char *name;                  /* switch name */
    char *backend_name;          /* backend method */
    char *script;                /* script to run for tap backends */
    char *downscript;            /* downscript to run for tap backends */
    uint16_t fp_ports;           /* front-panel port count */
    MACAddr fp_start_macaddr;    /* front-panel port 0 mac addr */

    /* front-panel ports */
    struct fp_port fp_port[ROCKER_FP_PORTS_MAX];
};

#define to_rocker(obj) \
    OBJECT_CHECK(struct rocker, (obj), ROCKER)

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

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = &r->fp_port[i];

        fp_port_clear_nic(port);
        fp_port_clear_netdev(port);
        fp_port_clear_conf(port);
    }

    memory_region_destroy(&r->mmio);
}

static int pci_rocker_init(PCIDevice *pci_dev)
{
    uint8_t *pci_conf = pci_dev->config;
    struct rocker *r = to_rocker(pci_dev);
    const MACAddr zero = { .a = { 0,0,0,0,0,0 } };
    const MACAddr dflt = { .a = { 0x52, 0x54, 0x00, 0x12, 0x35, 0x01 } };
    static int sw_index = 0;
    enum fp_port_backend backend;
    int i, err;

    pci_conf[PCI_INTERRUPT_PIN] = ROCKER_PCI_INTERRUPT_PIN;

    /* set up memory-mapped region at BAR0 */

    memory_region_init_io(&r->mmio, OBJECT(r), &rocker_mmio_ops, r,
                          "rocker-mmio", ROCKER_PCI_BAR0_SIZE);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &r->mmio);

    /* validate switch properties */

    if (!r->name)
        r->name = g_strdup(ROCKER);

    // XXX validate r->name is unique switch name

    if (memcmp(&r->fp_start_macaddr, &zero, sizeof(zero)) == 0) {
        memcpy(&r->fp_start_macaddr, &dflt, sizeof(dflt));
        r->fp_start_macaddr.a[4] += (sw_index++);
    }

    backend = FP_BACKEND_NONE;
    if (r->backend_name && memcmp(r->backend_name, "tap", sizeof("tap")) == 0)
        backend = FP_BACKEND_TAP;

    if (r->fp_ports > ROCKER_FP_PORTS_MAX)
        r->fp_ports = ROCKER_FP_PORTS_MAX;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = &r->fp_port[i];

        fp_port_set_conf(port, r->name, &r->fp_start_macaddr, r, i);
        err = fp_port_set_netdev(port, backend,
                                 r->script, r->downscript);
        if (err)
            goto err_set_netdev;
        err = fp_port_set_nic(port, object_get_typename(OBJECT(r)));
        if (err)
            goto err_set_nic;
    }

    return 0;

err_set_nic:
    fp_port_clear_netdev(&r->fp_port[i]);
err_set_netdev:
    for (--i; i >= 0; i--) {
        struct fp_port *port = &r->fp_port[i];
        fp_port_clear_nic(port);
        fp_port_clear_netdev(port);
        fp_port_clear_conf(port);
    }

    return -1;
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
