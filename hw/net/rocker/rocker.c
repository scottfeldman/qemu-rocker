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

/* PCI interface */

static void pci_rocker_uninit(PCIDevice *dev)
{
}

static int pci_rocker_init(PCIDevice *pci_dev)
{
    return 0;
}

static void qdev_rocker_reset(DeviceState *dev)
{
}

static Property rocker_properties[] = {
    DEFINE_NIC_PROPERTIES(rocker_state, conf),
    DEFINE_PROP_END_OF_LIST(),
};

#define PCI_VENDOR_ID_ROCKER      0x0666
#define PCI_DEVICE_ID_ROCKER      0x0001

static void rocker_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_rocker_init;
    k->exit = pci_rocker_uninit;
    k->vendor_id = PCI_VENDOR_ID_ROCKER;
    k->device_id = PCI_DEVICE_ID_ROCKER;
    k->revision = 0x01;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Rocker Switch";
    dc->reset = qdev_rocker_reset;
    dc->props = rocker_properties;
}

static const TypeInfo rocker_info = {
    .name          = TYPE_ROCKER,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(rocker_state),
    .class_init    = rocker_class_init,
};

static void rocker_register_types(void)
{
    type_register_static(&rocker_info);
}

type_init(rocker_register_types)
