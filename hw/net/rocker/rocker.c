/*
 * QEMU rocker switch emulation - PCI device
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@cumulusnetworks.com>
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
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

#if defined (DEBUG_ROCKER)
#  define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "ROCKER: " fmt, ## __VA_ARGS__); } while (0)
#else
static inline GCC_FMT_ATTR(1, 2) int DPRINTF(const char *fmt, ...)
{
    return 0;
}
#endif

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

    /* register backings */
    uint32_t test_reg;
    uint64_t test_reg64;
    dma_addr_t test_dma_addr;
    uint32_t test_dma_size;
    uint32_t irq_status;
    uint32_t irq_mask;
};

#define to_rocker(obj) \
    OBJECT_CHECK(struct rocker, (obj), ROCKER)

static void rocker_update_irq(struct rocker *r)
{
    PCIDevice *d = PCI_DEVICE(r);
    uint32_t isr = r->irq_status & r->irq_mask;

    DPRINTF("Set IRQ to %d (%04x %04x)\n", isr ? 1 : 0,
            r->irq_status, r->irq_mask);

    pci_set_irq(d, (isr != 0));
}

static void rocker_test_dma_ctrl(struct rocker *r, uint32_t val)
{
    PCIDevice *d = PCI_DEVICE(r);
    char *buf;
    int i;

    buf = malloc(r->test_dma_size);

    if (!buf) {
        DPRINTF("test dma buffer alloc failed");
        return;
    }

    switch (val) {
    case ROCKER_TEST_DMA_CTRL_CLEAR:
        memset(buf, 0, r->test_dma_size);
        break;
    case ROCKER_TEST_DMA_CTRL_FILL:
        memset(buf, 0x96, r->test_dma_size);
        break;
    case ROCKER_TEST_DMA_CTRL_INVERT:
        pci_dma_read(d, r->test_dma_addr, buf, r->test_dma_size);
        for (i = 0; i < r->test_dma_size; i++)
            buf[i] = ~buf[i];
        break;
    default:
        DPRINTF("not test dma control val=0x%08x\n", val);
        return;
    }
    pci_dma_write(d, r->test_dma_addr, buf, r->test_dma_size);
    r->irq_status |= ROCKER_IRQ_TEST_DMA_DONE;
    rocker_update_irq(r);
}

static void rocker_io_writel(void *opaque, hwaddr addr, uint32_t val)
{
    struct rocker *r = opaque;

    switch (addr) {
    case ROCKER_TEST_REG:
        r->test_reg = val;
        break;
    case ROCKER_TEST_IRQ:
        r->irq_status = val;
        rocker_update_irq(r);
        break;
    case ROCKER_IRQ_MASK:
        r->irq_mask = val;
        rocker_update_irq(r);
        break;
    case ROCKER_TEST_DMA_SIZE:
        r->test_dma_size = val;
        break;
    case ROCKER_TEST_DMA_CTRL:
        rocker_test_dma_ctrl(r, val);
        break;
    default:
        DPRINTF("not implemented write(l) addr=0x%lx val=0x%08x\n", addr, val);
        break;
    }
}

static void rocker_io_writeq(void *opaque, hwaddr addr, uint64_t val)
{
    struct rocker *r = opaque;

    switch (addr) {
    case ROCKER_TEST_REG64:
        r->test_reg64 = val;
        break;
    case ROCKER_TEST_DMA_ADDR:
        r->test_dma_addr = val;
        break;
    default:
        DPRINTF("not implemented write(q) addr=0x%lx val=0x%016lx\n", addr, val);
        break;
    }
}

static void rocker_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                              unsigned size)
{
    DPRINTF("Write addr %lx, size %u, val %lx\n", addr, size, val);

    switch (size) {
    case 4:
        rocker_io_writel(opaque, addr, val);
        break;
    case 8:
        rocker_io_writeq(opaque, addr, val);
        break;
    }
}

static uint32_t rocker_io_readl(void *opaque, hwaddr addr)
{
    struct rocker *r = opaque;
    uint32_t ret;

    switch (addr) {
    case ROCKER_TEST_REG:
        ret = r->test_reg * 2;
        break;
    case ROCKER_IRQ_STAT:
        ret = r->irq_status;
        r->irq_status = 0;
        rocker_update_irq(r);
        break;
    case ROCKER_IRQ_MASK:
        ret = r->irq_mask;
        break;
    case ROCKER_TEST_DMA_SIZE:
        ret = r->test_dma_size;
        break;
    default:
        DPRINTF("not implemented read(l) addr=0x%lx\n", addr);
        ret = 0;
        break;
    }
    return ret;
}

static uint64_t rocker_io_readq(void *opaque, hwaddr addr)
{
    struct rocker *r = opaque;
    uint64_t ret;

    switch (addr) {
    case ROCKER_TEST_REG64:
        ret = r->test_reg64 * 2;
        break;
    case ROCKER_TEST_DMA_ADDR:
        ret = r->test_dma_addr;
        break;
    default:
        DPRINTF("not implemented read(q) addr=0x%lx\n", addr);
        ret = 0;
        break;
    }
    return ret;
}

static uint64_t rocker_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    DPRINTF("Read addr %lx, size %u\n", addr, size);

    switch (size) {
    case 4:
        return rocker_io_readl(opaque, addr);
    case 8:
        return rocker_io_readq(opaque, addr);
    }

    return -1;
}

static const MemoryRegionOps rocker_mmio_ops = {
    .read = rocker_mmio_read,
    .write = rocker_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
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
