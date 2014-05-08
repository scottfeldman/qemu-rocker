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
#include "net/net.h"
#include "qemu/iov.h"
#include "qemu/bitops.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_desc.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_flow.h"
#include "rocker_l2l3.h"
#include "tlv_parse.h"

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
    char *world_dflt;            /* default world for ports */
    uint16_t fp_ports;           /* front-panel port count */
    MACAddr fp_start_macaddr;    /* front-panel port 0 mac addr */
    uint64_t switch_id;          /* switch id */

    /* front-panel ports */
    struct fp_port *fp_port[ROCKER_FP_PORTS_MAX];

    /* register backings */
    uint32_t test_reg;
    uint64_t test_reg64;
    dma_addr_t test_dma_addr;
    uint32_t test_dma_size;
    uint32_t irq_status;
    uint32_t irq_mask;

    /* desc rings */
    struct desc_ring *rings[4];

    /* switch worlds */
    struct world *worlds[ROCKER_WORLD_TYPE_MAX];
};

#define ROCKER "rocker"

#define to_rocker(obj) \
    OBJECT_CHECK(struct rocker, (obj), ROCKER)

#define TX_TLVS_MAX 6  // XXX define elsewheres

static int tx_consume(struct rocker *r, struct rocker_desc *desc)
{
    PCIDevice *dev = (PCIDevice *)r;
    char *buf = desc_get_buf(desc, dev, true);
    struct rocker_tlv *tlvs[TX_TLVS_MAX + 1], *tlv;
    struct iovec iov[16] = { { 0, }, };
    uint16_t lport = 0, port = 0;
    int iovcnt = 0, status = 0, i;
    hwaddr addr;

    if (!buf)
        return -ENXIO;

    if (!tlv_parse(buf, desc_tlv_size(desc), tlvs, TX_TLVS_MAX))
        return -EINVAL;

    for (tlv = *tlvs; tlv; tlv++) {
        switch (TLV_TYPE(tlv)) {
        case TLV_LPORT:
            lport = le16_to_cpu(tlv->value->lport);
            if (!fp_port_from_lport(lport, &port)) {
                status = -EINVAL;
                goto err_bad_lport;
            }
            break;
        case TLV_TX_OFFLOAD:
        case TLV_TX_L3_CSUM_OFF:
        case TLV_TX_TSO_MSS:
        case TLV_TX_TSO_HDR_LEN:
            // XXX ignored for now
            break;
        case TLV_TX_FRAGS:
            iovcnt = TLV_SIZE(tlv) / sizeof(tlv->value->tx_frag[0]);
            if (iovcnt > 16) {
                status = -EINVAL;
                goto err_too_many_frags;
            }
            for (i = 0; i < iovcnt; i++) {
                iov[i].iov_len = le16_to_cpu(tlv->value->tx_frag[i].len);
                iov[i].iov_base = g_malloc(iov[i].iov_len);
                if (!iov[i].iov_base) {
                    status = -ENOMEM;
                    goto err_no_mem;
                }
                addr = le64_to_cpu(tlv->value->tx_frag[i].addr);
                if (pci_dma_read(dev, addr, iov[i].iov_base, iov[i].iov_len)) {
                    status = -ENXIO;
                    goto err_bad_io;
                }
            }
            break;
        }
    }

    if (iovcnt) {
        ; // XXX perform Tx offloads
    }

    status = fp_port_eg(r->fp_port[port], iov, iovcnt);

err_bad_lport:
err_no_mem:
err_bad_io:
    for (i = 0; i < iovcnt; i++)
        if (iov[i].iov_base)
            g_free(iov[i].iov_base);

err_too_many_frags:
    desc_put_buf(buf);

    return status;
}

static int cmd_get_port_settings(struct rocker *r,
                                 struct rocker_desc *desc, char *buf,
                                 struct rocker_tlv *cmd_info_tlv)
{
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MAX + 1];
    struct fp_port *fp_port;
    uint16_t lport;
    uint16_t port;
    uint32_t speed;
    uint8_t duplex;
    uint8_t autoneg;
    MACAddr macaddr;
    size_t tlv_size;
    int pos;
    int err;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
                            cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_PORT])
        return -EINVAL;

    lport = rocker_tlv_get_u16(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_PORT]);
    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;
    fp_port = r->fp_port[port];

    err = fp_port_get_settings(fp_port, &speed, &duplex, &autoneg, macaddr);
    if (err)
        return err;

    tlv_size = rocker_tlv_total_size(sizeof(uint16_t)) +
               rocker_tlv_total_size(sizeof(uint32_t)) +
               rocker_tlv_total_size(sizeof(uint8_t)) +
               rocker_tlv_total_size(sizeof(uint8_t)) +
               rocker_tlv_total_size(sizeof(macaddr.a));

    if (tlv_size > desc_buf_size(desc))
        return -EMSGSIZE;

    pos = 0;
    rocker_tlv_put_u16(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_PORT, lport);
    rocker_tlv_put_u32(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_SPEED, speed);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX, duplex);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG, autoneg);
    rocker_tlv_put(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR,
                   sizeof(macaddr.a), macaddr.a);

    return 0;
}

static int cmd_set_port_settings(struct rocker *r,
                                 struct rocker_desc *desc, char *buf,
                                 struct rocker_tlv *cmd_info_tlv)
{
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MAX + 1];
    struct fp_port *fp_port;
    uint16_t lport;
    uint16_t port;
    uint32_t speed;
    uint8_t duplex;
    uint8_t autoneg;
    MACAddr macaddr;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
                            cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_PORT] ||
        !tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_SPEED] ||
        !tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX] ||
        !tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG] ||
        !tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR])
        return -EINVAL;

    lport = rocker_tlv_get_u16(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_PORT]);
    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;
    fp_port = r->fp_port[port];

    speed = rocker_tlv_get_u32(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_SPEED]);
    duplex = rocker_tlv_get_u8(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX]);
    autoneg = rocker_tlv_get_u8(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG]);

    if (rocker_tlv_len(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR]) !=
        sizeof(macaddr.a))
        return -EINVAL;

    memcpy(macaddr.a,
           rocker_tlv_data(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR]),
           sizeof(macaddr.a));

    return fp_port_set_settings(fp_port, speed, duplex, autoneg, macaddr);
}

static int cmd_consume(struct rocker *r, struct rocker_desc *desc)
{
    PCIDevice *d = (PCIDevice *)r;
    char *buf = desc_get_buf(desc, d, false);
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_MAX + 1];
    int err;

    if (!buf)
        return -ENXIO;

    rocker_tlv_parse(tlvs, ROCKER_TLV_CMD_MAX, buf, desc_tlv_size(desc));

    if (!tlvs[ROCKER_TLV_CMD_TYPE] || !tlvs[ROCKER_TLV_CMD_INFO]) {
        err = -EINVAL;
        goto buf_put;
    }

    /* This might be reworked to something like this:
     * Every world will have an array of command handlers from
     * ROCKER_TLV_CMD_TYPE_UNSPEC to ROCKER_TLV_CMD_TYPE_MAX. There is
     * up to each world to implement whatever command it want.
     * It can reference "generic" commands as cmd_set_port_settings or
     * cmd_get_port_settings
     */

    switch (rocker_tlv_get_u16(tlvs[ROCKER_TLV_CMD_TYPE])) {
    case ROCKER_TLV_CMD_TYPE_FLOW:
        err = world_do_cmd(r->worlds[ROCKER_WORLD_TYPE_FLOW],
                           tlvs[ROCKER_TLV_CMD_INFO]);
        break;
    case ROCKER_TLV_CMD_TYPE_TRUNK:
    case ROCKER_TLV_CMD_TYPE_BRIDGE:
        err = world_do_cmd(r->worlds[ROCKER_WORLD_TYPE_L2L3],
                           tlvs[ROCKER_TLV_CMD_INFO]);
        break;
    case ROCKER_TLV_CMD_TYPE_GET_PORT_SETTINGS:
        err = cmd_get_port_settings(r, desc, buf,
                                    tlvs[ROCKER_TLV_CMD_INFO]);
        break;
    case ROCKER_TLV_CMD_TYPE_SET_PORT_SETTINGS:
        err = cmd_set_port_settings(r, desc, buf,
                                    tlvs[ROCKER_TLV_CMD_INFO]);
        break;
    default:
        break;
    }
    err = 0;

buf_put:
    desc_put_buf(buf);

    return err;
}

void rocker_update_irq(struct rocker *r)
{
    PCIDevice *d = PCI_DEVICE(r);
    uint32_t isr = r->irq_status & r->irq_mask;

    DPRINTF("Set IRQ to %d (%04x %04x)\n", isr ? 1 : 0,
            r->irq_status, r->irq_mask);

    pci_set_irq(d, (isr != 0));
}

void rocker_irq_status_append(struct rocker *r, uint32_t irq_status)
{
    r->irq_status |= irq_status;
}

int rx_produce(struct world *world, uint16_t lport,
               const struct iovec *iov, int iovcnt)
{
    struct rocker *r = world_rocker(world);
    PCIDevice *dev = (PCIDevice *)r;
    struct desc_ring *ring = r->rings[ROCKER_RX_INDEX];
    struct rocker_desc *desc = desc_ring_fetch_desc(ring);
    struct rocker_tlv *tlv;
    size_t size = iov_size(iov, iovcnt);
    char *buf;
    uint16_t rx_flags = 0, rx_csum = 0;
    size_t tlv_size;
    int status = 0;

    if (!desc)
        return -ENOBUFS;

    tlv_size = TLV_LENGTH(sizeof(tlv->value->lport))
             + TLV_LENGTH(sizeof(tlv->value->rx_flags))
             + TLV_LENGTH(sizeof(tlv->value->rx_csum))
             + TLV_LENGTH(size)
             + 0;

    if (tlv_size > desc_buf_size(desc))
        return -ENOSPC;

    buf = g_malloc(tlv_size);
    if (!buf)
        return -ENOMEM;

    tlv = tlv_start(buf, TLV_LPORT, sizeof(tlv->value->lport));
    tlv->value->lport = cpu_to_le16(lport);

    tlv = tlv_add(tlv, TLV_RX_FLAGS, sizeof(tlv->value->rx_flags));
    tlv->value->rx_flags = cpu_to_le16(rx_flags);

    tlv = tlv_add(tlv, TLV_RX_CSUM, sizeof(tlv->value->rx_csum));
    tlv->value->rx_csum = cpu_to_le16(rx_csum);

    tlv = tlv_add(tlv, TLV_RX_PACKET, size);

    iov_to_buf(iov, iovcnt, 0, tlv->value->rx_packet, size);

    status = desc_set_buf(desc, dev, buf, tlv_size);

    desc_ring_post_desc(ring, desc, status);

    rocker_irq_status_append(r, ROCKER_IRQ_RX_DMA_DONE);
    rocker_update_irq(r);

    g_free(buf);

    return status;
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
    rocker_irq_status_append(r, ROCKER_IRQ_TEST_DMA_DONE);
    rocker_update_irq(r);
}

static void rocker_reset(DeviceState *dev);

static void rocker_control(struct rocker *r, uint32_t val)
{
    if (val & ROCKER_CONTROL_RESET)
        rocker_reset(DEVICE(r));
}

static void rocker_io_writel(void *opaque, hwaddr addr, uint32_t val)
{
    struct rocker *r = opaque;
    int index = ROCKER_RING_INDEX(addr);

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
    case ROCKER_TX_DMA_DESC_SIZE:
    case ROCKER_RX_DMA_DESC_SIZE:
    case ROCKER_CMD_DMA_DESC_SIZE:
    case ROCKER_EVENT_DMA_DESC_SIZE:
        desc_ring_set_size(r->rings[index], val);
        break;
    case ROCKER_TX_DMA_DESC_HEAD:
    case ROCKER_RX_DMA_DESC_HEAD:
    case ROCKER_CMD_DMA_DESC_HEAD:
    case ROCKER_EVENT_DMA_DESC_HEAD:
        if (desc_ring_set_head(r->rings[index], val)) {
            rocker_irq_status_append(r, (1 << (index + 1)));
            rocker_update_irq(r);
        }
        break;
    case ROCKER_TX_DMA_DESC_CTRL:
    case ROCKER_RX_DMA_DESC_CTRL:
    case ROCKER_CMD_DMA_DESC_CTRL:
    case ROCKER_EVENT_DMA_DESC_CTRL:
        desc_ring_set_ctrl(r->rings[index], val);
        break;
    case ROCKER_CONTROL:
        rocker_control(r, val);
        break;
    default:
        DPRINTF("not implemented write(l) addr=0x%lx val=0x%08x\n", addr, val);
        break;
    }
}

static void rocker_port_phys_mode_write(struct rocker *r, uint64_t new)
{
    int i;
    enum rocker_world_type old_type;
    enum rocker_world_type new_type;
    struct fp_port *fp_port;

    for (i = 0; i < r->fp_ports; i++) {
        fp_port = r->fp_port[i];
        old_type = world_type(fp_port_get_world(fp_port));
        new_type = ((new >> (i + 1)) & 0x1) ? ROCKER_WORLD_TYPE_FLOW :
                                              ROCKER_WORLD_TYPE_L2L3;
        if (new_type == old_type)
            continue;
        fp_port_set_world(fp_port, r->worlds[new_type]);
    }
}

static void rocker_port_phys_enable_write(struct rocker *r, uint64_t new)
{
    int i;
    bool old_enabled;
    bool new_enabled;
    struct fp_port *fp_port;

    for (i = 0; i < r->fp_ports; i++) {
        fp_port = r->fp_port[i];
        old_enabled = fp_port_enabled(fp_port);
        new_enabled = (new >> (i + 1)) & 0x1;
        if (new_enabled == old_enabled)
            continue;
        if (new_enabled)
            fp_port_enable(r->fp_port[i]);
        else
            fp_port_disable(r->fp_port[i]);
    }
}

static void rocker_io_writeq(void *opaque, hwaddr addr, uint64_t val)
{
    struct rocker *r = opaque;
    int index;

    switch (addr) {
    case ROCKER_TEST_REG64:
        r->test_reg64 = val;
        break;
    case ROCKER_TEST_DMA_ADDR:
        r->test_dma_addr = val;
        break;
    case ROCKER_TX_DMA_DESC_ADDR:
    case ROCKER_RX_DMA_DESC_ADDR:
    case ROCKER_CMD_DMA_DESC_ADDR:
    case ROCKER_EVENT_DMA_DESC_ADDR:
        index = ROCKER_RING_INDEX(addr);
        desc_ring_set_base_addr(r->rings[index], val);
        break;
    case ROCKER_PORT_PHYS_MODE:
        rocker_port_phys_mode_write(r, val);
        break;
    case ROCKER_PORT_PHYS_ENABLE:
        rocker_port_phys_enable_write(r, val);
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
    int index = ROCKER_RING_INDEX(addr);

    switch (addr) {
    case ROCKER_BOGUS_REG0:
    case ROCKER_BOGUS_REG1:
    case ROCKER_BOGUS_REG2:
    case ROCKER_BOGUS_REG3:
        ret = 0xDEADBABE;
        break;
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
    case ROCKER_PORT_PHYS_COUNT:
        ret = r->fp_ports;
        break;
    case ROCKER_TX_DMA_DESC_SIZE:
    case ROCKER_RX_DMA_DESC_SIZE:
    case ROCKER_CMD_DMA_DESC_SIZE:
    case ROCKER_EVENT_DMA_DESC_SIZE:
        ret = desc_ring_get_size(r->rings[index]);
        break;
    case ROCKER_TX_DMA_DESC_HEAD:
    case ROCKER_RX_DMA_DESC_HEAD:
    case ROCKER_CMD_DMA_DESC_HEAD:
    case ROCKER_EVENT_DMA_DESC_HEAD:
        ret = desc_ring_get_head(r->rings[index]);
        break;
    case ROCKER_TX_DMA_DESC_TAIL:
    case ROCKER_RX_DMA_DESC_TAIL:
    case ROCKER_CMD_DMA_DESC_TAIL:
    case ROCKER_EVENT_DMA_DESC_TAIL:
        ret = desc_ring_get_tail(r->rings[index]);
        break;
    case ROCKER_TX_DMA_DESC_CTRL:
    case ROCKER_RX_DMA_DESC_CTRL:
    case ROCKER_CMD_DMA_DESC_CTRL:
    case ROCKER_EVENT_DMA_DESC_CTRL:
        ret = desc_ring_get_ctrl(r->rings[index]);
        break;
    default:
        DPRINTF("not implemented read(l) addr=0x%lx\n", addr);
        ret = 0;
        break;
    }
    return ret;
}

static uint64_t rocker_port_phys_mode_read(struct rocker *r)
{
    int i;
    uint64_t status = 0;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = r->fp_port[i];

        if (world_type(fp_port_get_world(port)) == ROCKER_WORLD_TYPE_FLOW)
            status |= 1 << (i + 1);
    }
    return status;
}

static uint64_t rocker_port_phys_link_status(struct rocker *r)
{
    int i;
    uint64_t status = 0;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = r->fp_port[i];

        if (fp_port_get_link_up(port))
            status |= 1 << (i + 1);
    }
    return status;
}

static uint64_t rocker_port_phys_enable_read(struct rocker *r)
{
    int i;
    uint64_t ret = 0;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = r->fp_port[i];

        if (fp_port_enabled(port))
            ret |= 1 << (i + 1);
    }
    return ret;
}

static uint64_t rocker_io_readq(void *opaque, hwaddr addr)
{
    struct rocker *r = opaque;
    int index = ROCKER_RING_INDEX(addr);
    uint64_t ret;

    switch (addr) {
    case ROCKER_BOGUS_REG0:
    case ROCKER_BOGUS_REG2:
        ret = 0xDEADBABEDEADBABE;
        break;
    case ROCKER_TEST_REG64:
        ret = r->test_reg64 * 2;
        break;
    case ROCKER_TEST_DMA_ADDR:
        ret = r->test_dma_addr;
        break;
    case ROCKER_TX_DMA_DESC_ADDR:
    case ROCKER_RX_DMA_DESC_ADDR:
    case ROCKER_CMD_DMA_DESC_ADDR:
    case ROCKER_EVENT_DMA_DESC_ADDR:
        ret = desc_ring_get_base_addr(r->rings[index]);
        break;
    case ROCKER_PORT_PHYS_MODE:
        ret = rocker_port_phys_mode_read(r);
        break;
    case ROCKER_PORT_PHYS_LINK_STATUS:
        ret = rocker_port_phys_link_status(r);
        break;
    case ROCKER_PORT_PHYS_ENABLE:
        ret = rocker_port_phys_enable_read(r);
        break;
    case ROCKER_SWITCH_ID:
        ret = r->switch_id;
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
        struct fp_port *port = r->fp_port[i];

        fp_port_clear_nic(port);
        fp_port_clear_netdev(port);
        fp_port_clear_conf(port);
        fp_port_free(port);
        r->fp_port[i] = NULL;
    }

    for (i = 0; i < 4; i++)
        if (r->rings[i])
             desc_ring_free(r->rings[i]);

    memory_region_destroy(&r->mmio);

    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (r->worlds[i])
            world_free(r->worlds[i]);
}

static struct world *rocker_default_world(struct rocker *r)
{
    struct world *world_dflt;

    world_dflt = r->worlds[ROCKER_WORLD_TYPE_L2L3];
    if (r->world_dflt) {
        if (strcmp(r->world_dflt, "flow") == 0)
            world_dflt = r->worlds[ROCKER_WORLD_TYPE_FLOW];
        else if (strcmp(r->world_dflt, "l2l3") == 0)
            world_dflt = r->worlds[ROCKER_WORLD_TYPE_L2L3];
    }
    return world_dflt;
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

    /* allocate worlds */

    r->worlds[ROCKER_WORLD_TYPE_FLOW] = flow_world_alloc(r);
    r->worlds[ROCKER_WORLD_TYPE_L2L3] = l2l3_world_alloc(r);

    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (!r->worlds[i])
            goto err_world_alloc;

    /* setup PCI device */

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

    if (!r->switch_id)
        memcpy(&r->switch_id, &r->fp_start_macaddr,
               sizeof(r->fp_start_macaddr));

    backend = FP_BACKEND_NONE;
    if (r->backend_name && memcmp(r->backend_name, "tap", sizeof("tap")) == 0)
        backend = FP_BACKEND_TAP;

    if (r->fp_ports > ROCKER_FP_PORTS_MAX)
        r->fp_ports = ROCKER_FP_PORTS_MAX;

    r->rings[ROCKER_TX_INDEX] = desc_ring_alloc(r, ROCKER_TX_INDEX, tx_consume);
    r->rings[ROCKER_RX_INDEX] = desc_ring_alloc(r, ROCKER_RX_INDEX, NULL);
    r->rings[ROCKER_CMD_INDEX] = desc_ring_alloc(r, ROCKER_CMD_INDEX,
                                                 cmd_consume);
    r->rings[ROCKER_EVENT_INDEX] = desc_ring_alloc(r, ROCKER_EVENT_INDEX, NULL);

    for (i = 0; i < 4; i++)
        if (!r->rings[i])
            goto err_ring_alloc;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = fp_port_alloc();

        if (!port)
            goto err_port_alloc;

        r->fp_port[i] = port;

        fp_port_set_world(port, rocker_default_world(r));
        fp_port_set_conf(port, r, r->name, &r->fp_start_macaddr, i);
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
    fp_port_clear_netdev(r->fp_port[i]);
err_set_netdev:
    fp_port_free(r->fp_port[i]);
err_port_alloc:
    for (--i; i >= 0; i--) {
        struct fp_port *port = r->fp_port[i];
        fp_port_clear_nic(port);
        fp_port_clear_netdev(port);
        fp_port_clear_conf(port);
        fp_port_free(port);
    }
err_ring_alloc:
    for (i = 0; i < 4; i++)
        if (r->rings[i])
             desc_ring_free(r->rings[i]);
    memory_region_destroy(&r->mmio);
err_world_alloc:
    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (r->worlds[i])
            world_free(r->worlds[i]);

    return -1;
}

static void rocker_reset(DeviceState *dev)
{
    struct rocker *r = to_rocker(dev);
    int i;

    for (i = 0; i < r->fp_ports; i++) {
        fp_port_reset(r->fp_port[i]);
        fp_port_set_world(r->fp_port[i], rocker_default_world(r));
    }

    r->test_reg = 0;
    r->test_reg64 = 0;
    r->test_dma_addr = 0;
    r->test_dma_size = 0;
    r->irq_status = 0;
    r->irq_mask = 0;

    desc_ring_reset(r->rings[ROCKER_TX_INDEX]);
    desc_ring_reset(r->rings[ROCKER_RX_INDEX]);
    desc_ring_reset(r->rings[ROCKER_CMD_INDEX]);
    desc_ring_reset(r->rings[ROCKER_EVENT_INDEX]);

    DPRINTF("Reset done\n");
}

static Property rocker_properties[] = {
    DEFINE_PROP_STRING("name", struct rocker, name),
    DEFINE_PROP_STRING("backend", struct rocker, backend_name),
    DEFINE_PROP_STRING("script", struct rocker, script),
    DEFINE_PROP_STRING("downscript", struct rocker, downscript),
    DEFINE_PROP_STRING("world", struct rocker, world_dflt),
    DEFINE_PROP_UINT16("fp_ports", struct rocker,
                       fp_ports, 16),
    DEFINE_PROP_MACADDR("fp_start_macaddr", struct rocker,
                        fp_start_macaddr),
    DEFINE_PROP_UINT64("switch_id", struct rocker,
                       switch_id, 0),
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
