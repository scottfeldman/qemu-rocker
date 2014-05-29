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
#include "hw/pci/msix.h"
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

struct rocker {
    /* private */
    PCIDevice parent_obj;
    /* public */

    MemoryRegion mmio;
    MemoryRegion msix_bar;

    /* switch configuration */
    char *name;                  /* switch name */
    uint32_t fp_ports;           /* front-panel port count */
    NICPeers *fp_ports_peers;
    MACAddr fp_start_macaddr;    /* front-panel port 0 mac addr */
    uint64_t switch_id;          /* switch id */

    /* front-panel ports */
    struct fp_port *fp_port[ROCKER_FP_PORTS_MAX];

    /* register backings */
    uint32_t test_reg;
    uint64_t test_reg64;
    dma_addr_t test_dma_addr;
    uint32_t test_dma_size;

    /* desc rings */
    struct desc_ring **rings;

    /* switch worlds */
    struct world *worlds[ROCKER_WORLD_TYPE_MAX];
    struct world *world_dflt;
};

#define ROCKER "rocker"

#define to_rocker(obj) \
    OBJECT_CHECK(struct rocker, (obj), ROCKER)

static uint32_t rocker_get_lport_by_tx_ring(struct rocker *r,
                                            struct desc_ring *ring)
{
    return (desc_ring_index(ring) - 2) / 2 + 1;
}

static int tx_consume(struct rocker *r, struct desc_info *info)
{
    PCIDevice *dev = PCI_DEVICE(r);
    char *buf = desc_get_buf(info, true);
    struct rocker_tlv *tlv_frag;
    struct rocker_tlv *tlvs[ROCKER_TLV_TX_MAX + 1];
    struct iovec iov[ROCKER_TX_FRAGS_MAX] = { { 0, }, };
    uint32_t lport;
    uint32_t port;
    uint16_t tx_offload = ROCKER_TX_OFFLOAD_NONE;
    uint16_t tx_l3_csum_off = 0;
    uint16_t tx_tso_mss = 0;
    uint16_t tx_tso_hdr_len = 0;
    int iovcnt = 0;
    int err = 0;
    int rem;
    int i;

    if (!buf)
        return -ENXIO;

    rocker_tlv_parse(tlvs, ROCKER_TLV_TX_MAX, buf, desc_tlv_size(info));

    if (!tlvs[ROCKER_TLV_TX_FRAGS])
        return -EINVAL;

    lport = rocker_get_lport_by_tx_ring(r, desc_get_ring(info));
    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;

    if (tlvs[ROCKER_TLV_TX_OFFLOAD])
        tx_offload = rocker_tlv_get_u8(tlvs[ROCKER_TLV_TX_OFFLOAD]);

    switch (tx_offload) {
        case ROCKER_TX_OFFLOAD_L3_CSUM:
        if (!tlvs[ROCKER_TLV_TX_L3_CSUM_OFF])
            return -EINVAL;
        case ROCKER_TX_OFFLOAD_TSO:
        if (!tlvs[ROCKER_TLV_TX_TSO_MSS] ||
            !tlvs[ROCKER_TLV_TX_TSO_HDR_LEN])
            return -EINVAL;
    }

    if (tlvs[ROCKER_TLV_TX_L3_CSUM_OFF])
        tx_l3_csum_off = rocker_tlv_get_le16(tlvs[ROCKER_TLV_TX_L3_CSUM_OFF]);

    if (tlvs[ROCKER_TLV_TX_TSO_MSS])
        tx_tso_mss = rocker_tlv_get_le16(tlvs[ROCKER_TLV_TX_TSO_MSS]);

    if (tlvs[ROCKER_TLV_TX_TSO_HDR_LEN])
        tx_tso_hdr_len = rocker_tlv_get_le16(tlvs[ROCKER_TLV_TX_TSO_HDR_LEN]);

    rocker_tlv_for_each_nested(tlv_frag, tlvs[ROCKER_TLV_TX_FRAGS], rem) {
        hwaddr frag_addr;
        uint16_t frag_len;

        if (rocker_tlv_type(tlv_frag) != ROCKER_TLV_TX_FRAG)
            return -EINVAL;

        rocker_tlv_parse_nested(tlvs, ROCKER_TLV_TX_FRAG_ATTR_MAX, tlv_frag);
        
        if (!tlvs[ROCKER_TLV_TX_FRAG_ATTR_ADDR] ||
            !tlvs[ROCKER_TLV_TX_FRAG_ATTR_LEN])
            return -EINVAL;

        frag_addr = rocker_tlv_get_le64(tlvs[ROCKER_TLV_TX_FRAG_ATTR_ADDR]);
        frag_len = rocker_tlv_get_le16(tlvs[ROCKER_TLV_TX_FRAG_ATTR_LEN]);

        iov[iovcnt].iov_len = frag_len;
        iov[iovcnt].iov_base = g_malloc(frag_len);
        if (!iov[iovcnt].iov_base) {
            err = -ENOMEM;
            goto err_no_mem;
        }

        if (pci_dma_read(dev, frag_addr, iov[iovcnt].iov_base,
                     iov[iovcnt].iov_len)) {
            err = -ENXIO;
            goto err_bad_io;
        }

        if (++iovcnt > ROCKER_TX_FRAGS_MAX)
            goto err_too_many_frags;
    }

    if (iovcnt) {
        // XXX perform Tx offloads
        // XXX   silence compiler for now
        tx_l3_csum_off += tx_tso_mss = tx_tso_hdr_len = 0;
    }

    err = fp_port_eg(r->fp_port[port], iov, iovcnt);

err_no_mem:
err_bad_io:
err_too_many_frags:
    for (i = 0; i < iovcnt; i++)
        if (iov[i].iov_base)
            g_free(iov[i].iov_base);

    return err;
}

static int cmd_get_port_settings(struct rocker *r,
                                 struct desc_info *info, char *buf,
                                 struct rocker_tlv *cmd_info_tlv)
{
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MAX + 1];
    struct rocker_tlv *nest;
    struct fp_port *fp_port;
    uint32_t lport;
    uint32_t port;
    uint32_t speed;
    uint8_t duplex;
    uint8_t autoneg;
    MACAddr macaddr;
    enum rocker_world_type mode;
    size_t tlv_size;
    int pos;
    int err;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
                            cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_LPORT])
        return -EINVAL;

    lport = rocker_tlv_get_le32(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_LPORT]);
    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;
    fp_port = r->fp_port[port];

    err = fp_port_get_settings(fp_port, &speed, &duplex, &autoneg);
    if (err)
        return err;

    fp_port_get_macaddr(fp_port, macaddr);
    mode = world_type(fp_port_get_world(fp_port));

    tlv_size = rocker_tlv_total_size(0) +                 /* nest */
               rocker_tlv_total_size(sizeof(uint32_t)) +  /*   lport */
               rocker_tlv_total_size(sizeof(uint32_t)) +  /*   speed */
               rocker_tlv_total_size(sizeof(uint8_t)) +   /*   duplex */
               rocker_tlv_total_size(sizeof(uint8_t)) +   /*   autoneg */
               rocker_tlv_total_size(sizeof(macaddr.a)) + /*   macaddr */
               rocker_tlv_total_size(sizeof(uint8_t));    /*   mode */

    if (tlv_size > desc_buf_size(info))
        return -EMSGSIZE;

    pos = 0;
    nest = rocker_tlv_nest_start(buf, &pos, ROCKER_TLV_CMD_INFO);
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_LPORT, lport);
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_SPEED, speed);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX, duplex);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG, autoneg);
    rocker_tlv_put(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR,
                   sizeof(macaddr.a), macaddr.a);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_CMD_PORT_SETTINGS_MODE, mode);
    rocker_tlv_nest_end(buf, &pos, nest);

    return desc_set_buf(info, tlv_size);
}

static int cmd_set_port_settings(struct rocker *r,
                                 struct rocker_tlv *cmd_info_tlv)
{
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MAX + 1];
    struct fp_port *fp_port;
    uint32_t lport;
    uint32_t port;
    uint32_t speed;
    uint8_t duplex;
    uint8_t autoneg;
    MACAddr macaddr;
    enum rocker_world_type mode;
    int err;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
                            cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_LPORT])
        return -EINVAL;

    lport = rocker_tlv_get_le32(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_LPORT]);
    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;
    fp_port = r->fp_port[port];

    if (tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_SPEED] &&
        tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX] &&
        tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG]) {

        speed = rocker_tlv_get_le32(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_SPEED]);
        duplex = rocker_tlv_get_u8(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX]);
        autoneg = rocker_tlv_get_u8(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG]);

        err = fp_port_set_settings(fp_port, speed, duplex, autoneg);
        if (err)
            return err;
    }

    if (tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR]) {
        if (rocker_tlv_len(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR]) !=
            sizeof(macaddr.a))
            return -EINVAL;
        memcpy(macaddr.a,
               rocker_tlv_data(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR]),
               sizeof(macaddr.a));
        fp_port_set_macaddr(fp_port, macaddr);
    }

    if (tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MODE]) {
        mode = rocker_tlv_get_u8(tlvs[ROCKER_TLV_CMD_PORT_SETTINGS_MODE]);
        fp_port_set_world(fp_port, r->worlds[mode]);
    }

    return 0;
}

static int cmd_consume(struct rocker *r, struct desc_info *info)
{
    char *buf = desc_get_buf(info, false);
    struct rocker_tlv *tlvs[ROCKER_TLV_CMD_MAX + 1];
    struct rocker_tlv *info_tlv;
    struct world *world;
    uint16_t cmd;
    int err;

    if (!buf)
        return -ENXIO;

    rocker_tlv_parse(tlvs, ROCKER_TLV_CMD_MAX, buf, desc_tlv_size(info));

    if (!tlvs[ROCKER_TLV_CMD_TYPE] || !tlvs[ROCKER_TLV_CMD_INFO])
        return -EINVAL;

    cmd = rocker_tlv_get_le16(tlvs[ROCKER_TLV_CMD_TYPE]);
    info_tlv = tlvs[ROCKER_TLV_CMD_INFO];

    /* This might be reworked to something like this:
     * Every world will have an array of command handlers from
     * ROCKER_TLV_CMD_TYPE_UNSPEC to ROCKER_TLV_CMD_TYPE_MAX. There is
     * up to each world to implement whatever command it want.
     * It can reference "generic" commands as cmd_set_port_settings or
     * cmd_get_port_settings
     */

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_FLOW_ADD:
    case ROCKER_TLV_CMD_TYPE_FLOW_MOD:
    case ROCKER_TLV_CMD_TYPE_FLOW_DEL:
    case ROCKER_TLV_CMD_TYPE_FLOW_GET_STATS:
        world = r->worlds[ROCKER_WORLD_TYPE_FLOW];
        err = world_do_cmd(world, info, buf, cmd, info_tlv);
        break;
    case ROCKER_TLV_CMD_TYPE_TRUNK:
    case ROCKER_TLV_CMD_TYPE_BRIDGE:
        world = r->worlds[ROCKER_WORLD_TYPE_L2L3];
        err = world_do_cmd(world, info, buf, cmd, info_tlv);
        break;
    case ROCKER_TLV_CMD_TYPE_GET_PORT_SETTINGS:
        err = cmd_get_port_settings(r, info, buf, info_tlv);
        break;
    case ROCKER_TLV_CMD_TYPE_SET_PORT_SETTINGS:
        err = cmd_set_port_settings(r, info_tlv);
        break;
    default:
        err = -EINVAL;
        break;
    }

    return err;
}

static void rocker_msix_irq(struct rocker *r, unsigned vector)
{
    PCIDevice *dev = PCI_DEVICE(r);

    DPRINTF("MSI-X notify request for vector %d\n", vector);
    if (vector >= ROCKER_MSIX_VEC_COUNT(r->fp_ports)) {
        DPRINTF("incorrect vector %d\n", vector);
        return;
    }
    msix_notify(dev, vector);
}

int rocker_event_link_changed(struct rocker *r, uint32_t lport, bool link_up)
{
    struct desc_ring *ring = r->rings[1];
    struct desc_info *info = desc_ring_fetch_desc(ring);
    struct rocker_tlv *nest;
    char *buf;
    size_t tlv_size;
    int pos;
    int err;

    if (!info)
        return -ENOBUFS;

    tlv_size = rocker_tlv_total_size(sizeof(uint16_t)) +  /* event type */
               rocker_tlv_total_size(0) +                 /* nest */
               rocker_tlv_total_size(sizeof(uint32_t)) +  /*   lport */
               rocker_tlv_total_size(sizeof(uint8_t));    /*   link up */

    if (tlv_size > desc_buf_size(info)) {
        err = -EMSGSIZE;
        goto err_too_big;
    }

    buf = desc_get_buf(info, false);
    if (!buf) {
        err = -ENOMEM;
        goto err_no_mem;
    }

    pos = 0;
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_EVENT_TYPE,
                        ROCKER_TLV_EVENT_TYPE_LINK_CHANGED);
    nest = rocker_tlv_nest_start(buf, &pos, ROCKER_TLV_EVENT_INFO);
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_EVENT_LINK_CHANGED_LPORT, lport);
    rocker_tlv_put_u8(buf, &pos, ROCKER_TLV_EVENT_LINK_CHANGED_LINKUP,
                      link_up ? 1 : 0);
    rocker_tlv_nest_end(buf, &pos, nest);

    err = desc_set_buf(info, tlv_size);

err_too_big:
err_no_mem:
    if (desc_ring_post_desc(ring, err))
        rocker_msix_irq(r, ROCKER_MSIX_VEC_EVENT);

    return err;
}

static struct desc_ring *rocker_get_rx_ring_by_lport(struct rocker *r,
                                                     uint32_t lport)
{
    return r->rings[(lport - 1) * 2 + 3];
}

int rx_produce(struct world *world, uint32_t lport,
               const struct iovec *iov, int iovcnt)
{
    struct rocker *r = world_rocker(world);
    PCIDevice *dev = (PCIDevice *)r;
    struct desc_ring *ring = rocker_get_rx_ring_by_lport(r, lport);
    struct desc_info *info = desc_ring_fetch_desc(ring);
    char *data;
    size_t data_size = iov_size(iov, iovcnt);
    char *buf;
    uint16_t rx_flags = 0;
    uint16_t rx_csum = 0;
    size_t tlv_size;
    struct rocker_tlv *tlvs[ROCKER_TLV_RX_MAX + 1];
    hwaddr frag_addr;
    uint16_t frag_max_len;
    int pos;
    int err;

    if (!info)
        return -ENOBUFS;

    buf = desc_get_buf(info, false);
    if (!buf) {
        err = -ENXIO;
        goto out;
    }
    rocker_tlv_parse(tlvs, ROCKER_TLV_RX_MAX, buf, desc_tlv_size(info));

    if (!tlvs[ROCKER_TLV_RX_FRAG_ADDR] ||
        !tlvs[ROCKER_TLV_RX_FRAG_MAX_LEN]) {
        err = -EINVAL;
        goto out;
    }

    frag_addr = rocker_tlv_get_le64(tlvs[ROCKER_TLV_RX_FRAG_ADDR]);
    frag_max_len = rocker_tlv_get_le16(tlvs[ROCKER_TLV_RX_FRAG_MAX_LEN]);

    if (data_size > frag_max_len) {
        err = -EMSGSIZE;
        goto out;
    }

    // XXX calc rx flags/csum

    tlv_size = rocker_tlv_total_size(sizeof(uint16_t)) + /* flags */
               rocker_tlv_total_size(sizeof(uint16_t)) + /* scum */
               rocker_tlv_total_size(sizeof(uint64_t)) + /* frag addr */
               rocker_tlv_total_size(sizeof(uint16_t)) + /* frag max len */
               rocker_tlv_total_size(sizeof(uint16_t));  /* frag len */

    if (tlv_size > desc_buf_size(info)) {
        err = -EMSGSIZE;
        goto out;
    }

    /* TODO:
     * iov dma write can be optimized in similar way e1000 does it in
     * e1000_receive_iov. But maybe if would make sense to introduce
     * generic helper iov_dma_write.
     */

    data = g_malloc(data_size);
    if (!data) {
        err = -ENOMEM;
        goto out;
    }
    iov_to_buf(iov, iovcnt, 0, data, data_size);
    pci_dma_write(dev, frag_addr, data, data_size);
    g_free(data);

    pos = 0;
    rocker_tlv_put_le16(buf, &pos, ROCKER_TLV_RX_FLAGS, rx_flags);
    rocker_tlv_put_le16(buf, &pos, ROCKER_TLV_RX_CSUM, rx_csum);
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_RX_FRAG_ADDR, frag_addr);
    rocker_tlv_put_le16(buf, &pos, ROCKER_TLV_RX_FRAG_MAX_LEN, frag_max_len);
    rocker_tlv_put_le16(buf, &pos, ROCKER_TLV_RX_FRAG_LEN, data_size);

    err = desc_set_buf(info, tlv_size);

out:
    if (desc_ring_post_desc(ring, err))
        rocker_msix_irq(r, ROCKER_MSIX_VEC_RX(lport - 1));

    return err;
}

int rocker_port_eg(struct rocker *r, uint32_t lport,
                   const struct iovec *iov, int iovcnt)
{
    struct fp_port *fp_port;
    uint32_t port;

    if (!fp_port_from_lport(lport, &port))
        return -EINVAL;

    fp_port = r->fp_port[port];

    return fp_port_eg(fp_port, iov, iovcnt);
}

static void rocker_test_dma_ctrl(struct rocker *r, uint32_t val)
{
    PCIDevice *dev = PCI_DEVICE(r);
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
        pci_dma_read(dev, r->test_dma_addr, buf, r->test_dma_size);
        for (i = 0; i < r->test_dma_size; i++)
            buf[i] = ~buf[i];
        break;
    default:
        DPRINTF("not test dma control val=0x%08x\n", val);
        return;
    }
    pci_dma_write(dev, r->test_dma_addr, buf, r->test_dma_size);

    rocker_msix_irq(r, ROCKER_MSIX_VEC_TEST);
}

static void rocker_reset(DeviceState *dev);

static void rocker_control(struct rocker *r, uint32_t val)
{
    if (val & ROCKER_CONTROL_RESET)
        rocker_reset(DEVICE(r));
}

static int rocker_pci_ring_count(struct rocker *r)
{
    /* There are:
     * - command ring
     * - event ring
     * - tx and rx ring per each port
     */
    return 2 + (2 * r->fp_ports);
}

static bool rocker_addr_is_desc_reg(struct rocker *r, hwaddr addr)
{
    hwaddr start = ROCKER_DMA_DESC_BASE;
    hwaddr end = start + (ROCKER_DMA_DESC_SIZE * rocker_pci_ring_count(r));

    return addr >= start && addr < end;
}

static void rocker_io_writel(void *opaque, hwaddr addr, uint32_t val)
{
    struct rocker *r = opaque;

    if (rocker_addr_is_desc_reg(r, addr)) {
        unsigned index = ROCKER_RING_INDEX(addr);
        unsigned offset = addr & ROCKER_DMA_DESC_MASK;

        switch (offset) {
        case ROCKER_DMA_DESC_SIZE_OFFSET:
            desc_ring_set_size(r->rings[index], val);
            break;
        case ROCKER_DMA_DESC_HEAD_OFFSET:
            if (desc_ring_set_head(r->rings[index], val))
                rocker_msix_irq(r, desc_ring_get_msix_vector(r->rings[index]));
            break;
        case ROCKER_DMA_DESC_CTRL_OFFSET:
            desc_ring_set_ctrl(r->rings[index], val);
            break;
        case ROCKER_DMA_DESC_CREDITS_OFFSET:
            if (desc_ring_ret_credits(r->rings[index], val))
                rocker_msix_irq(r, desc_ring_get_msix_vector(r->rings[index]));
            break;
        default:
            DPRINTF("not implemented dma reg write(l) addr=0x%lx val=0x%08x (ring %d, addr=0x%02x)\n",
                    addr, val, index, offset);
            break;
        }
        return;
    }

    switch (addr) {
    case ROCKER_TEST_REG:
        r->test_reg = val;
        break;
    case ROCKER_TEST_IRQ:
        rocker_msix_irq(r, val);
        break;
    case ROCKER_TEST_DMA_SIZE:
        r->test_dma_size = val;
        break;
    case ROCKER_TEST_DMA_CTRL:
        rocker_test_dma_ctrl(r, val);
        break;
    case ROCKER_CONTROL:
        rocker_control(r, val);
        break;
    default:
        DPRINTF("not implemented write(l) addr=0x%lx val=0x%08x\n", addr, val);
        break;
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

    if (rocker_addr_is_desc_reg(r, addr)) {
        unsigned index = ROCKER_RING_INDEX(addr);
        unsigned offset = addr & ROCKER_DMA_DESC_MASK;

        switch (offset) {
        case ROCKER_DMA_DESC_ADDR_OFFSET:
            desc_ring_set_base_addr(r->rings[index], val);
            break;
        default:
            DPRINTF("not implemented dma reg write(q) addr=0x%lx val=0x%016lx (ring %d, addr=0x%02x)\n",
                    addr, val, index, offset);
            break;
        }
        return;
    }

    switch (addr) {
    case ROCKER_TEST_REG64:
        r->test_reg64 = val;
        break;
    case ROCKER_TEST_DMA_ADDR:
        r->test_dma_addr = val;
        break;
    case ROCKER_PORT_PHYS_ENABLE:
        rocker_port_phys_enable_write(r, val);
        break;
    default:
        DPRINTF("not implemented write(q) addr=0x%lx val=0x%016lx\n", addr, val);
        break;
    }
}

#ifdef DEBUG_ROCKER
#define regname(reg) case (reg): return #reg
static const char *rocker_reg_name(void *opaque, hwaddr addr)
{
    struct rocker *r = opaque;

    if (rocker_addr_is_desc_reg(r, addr)) {
        unsigned index = ROCKER_RING_INDEX(addr);
        unsigned offset = addr & ROCKER_DMA_DESC_MASK;
        static char buf[100];
        char ring_name[10];

        switch (index) {
            case 0:
                sprintf(ring_name, "cmd");
                break;
            case 1:
                sprintf(ring_name, "event");
                break;
            default:
                sprintf(ring_name, "%s-%d", index % 2 ? "rx" : "tx",
                        (index - 2) / 2); 
        }

        switch (offset) {
        case ROCKER_DMA_DESC_ADDR_OFFSET:
            sprintf(buf, "Ring[%s] ADDR", ring_name);
            return buf;
        case ROCKER_DMA_DESC_SIZE_OFFSET:
            sprintf(buf, "Ring[%s] SIZE", ring_name);
            return buf;
        case ROCKER_DMA_DESC_HEAD_OFFSET:
            sprintf(buf, "Ring[%s] HEAD", ring_name);
            return buf;
        case ROCKER_DMA_DESC_TAIL_OFFSET:
            sprintf(buf, "Ring[%s] TAIL", ring_name);
            return buf;
        case ROCKER_DMA_DESC_CTRL_OFFSET:
            sprintf(buf, "Ring[%s] CTRL", ring_name);
            return buf;
        case ROCKER_DMA_DESC_CREDITS_OFFSET:
            sprintf(buf, "Ring[%s] CREDITS", ring_name);
            return buf;
        default:
            sprintf(buf, "Ring[%s] ???", ring_name);
            return buf;
        }
    } else {
        switch (addr) {
            regname(ROCKER_BOGUS_REG0);
            regname(ROCKER_BOGUS_REG1);
            regname(ROCKER_BOGUS_REG2);
            regname(ROCKER_BOGUS_REG3);
            regname(ROCKER_TEST_REG);
            regname(ROCKER_TEST_REG64);
            regname(ROCKER_TEST_IRQ);
            regname(ROCKER_TEST_DMA_ADDR);
            regname(ROCKER_TEST_DMA_SIZE);
            regname(ROCKER_TEST_DMA_CTRL);
            regname(ROCKER_CONTROL);
            regname(ROCKER_PORT_PHYS_COUNT);
            regname(ROCKER_PORT_PHYS_LINK_STATUS);
            regname(ROCKER_PORT_PHYS_ENABLE);
            regname(ROCKER_SWITCH_ID);
        }
    }
    return "???";
}
#endif

static void rocker_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                              unsigned size)
{
    DPRINTF("Write %s addr %lx, size %u, val %lx\n",
            rocker_reg_name(opaque, addr), addr, size, val);

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

    if (rocker_addr_is_desc_reg(r, addr)) {
        unsigned index = ROCKER_RING_INDEX(addr);
        unsigned offset = addr & ROCKER_DMA_DESC_MASK;

        switch (offset) {
        case ROCKER_DMA_DESC_SIZE_OFFSET:
            ret = desc_ring_get_size(r->rings[index]);
            break;
        case ROCKER_DMA_DESC_HEAD_OFFSET:
            ret = desc_ring_get_head(r->rings[index]);
            break;
        case ROCKER_DMA_DESC_TAIL_OFFSET:
            ret = desc_ring_get_tail(r->rings[index]);
            break;
        case ROCKER_DMA_DESC_CTRL_OFFSET:
            ret = desc_ring_get_ctrl(r->rings[index]);
            break;
        case ROCKER_DMA_DESC_CREDITS_OFFSET:
            ret = desc_ring_get_credits(r->rings[index]);
            break;
        default:
            DPRINTF("not implemented dma reg read(l) addr=0x%lx (ring %d, addr=0x%02x)\n",
                    addr, index, offset);
            ret = 0;
            break;
        }
        return ret;
    }

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
    case ROCKER_TEST_DMA_SIZE:
        ret = r->test_dma_size;
        break;
    case ROCKER_PORT_PHYS_COUNT:
        ret = r->fp_ports;
        break;
    default:
        DPRINTF("not implemented read(l) addr=0x%lx\n", addr);
        ret = 0;
        break;
    }
    return ret;
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
    uint64_t ret;

    if (rocker_addr_is_desc_reg(r, addr)) {
        unsigned index = ROCKER_RING_INDEX(addr);
        unsigned offset = addr & ROCKER_DMA_DESC_MASK;

        switch (addr & ROCKER_DMA_DESC_MASK) {
        case ROCKER_DMA_DESC_ADDR_OFFSET:
            ret = desc_ring_get_base_addr(r->rings[index]);
            break;
        default:
            DPRINTF("not implemented dma reg read(q) addr=0x%lx (ring %d, addr=0x%02x)\n",
                    addr, index, offset);
            ret = 0;
            break;
        }
        return ret;
    }

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
    DPRINTF("Read %s addr %lx, size %u\n",
            rocker_reg_name(opaque, addr), addr, size);

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

static void rocker_msix_vectors_unuse(struct rocker *r,
                                      unsigned int num_vectors)
{
    PCIDevice *dev = PCI_DEVICE(r);
    int i;

    for (i = 0; i < num_vectors; i++) {
        msix_vector_unuse(dev, i);
    }
}

static int rocker_msix_vectors_use(struct rocker *r,
                                   unsigned int num_vectors)
{
    PCIDevice *dev = PCI_DEVICE(r);
    int err;
    int i;

    for (i = 0; i < num_vectors; i++) {
        err = msix_vector_use(dev, i);
        if (err)
            goto rollback;
    }
    return 0;

rollback:
    rocker_msix_vectors_unuse(r, i);
    return err;
}

static int rocker_msix_init(struct rocker *r)
{
    PCIDevice *dev = PCI_DEVICE(r);
    int err;

    err = msix_init(dev, ROCKER_MSIX_VEC_COUNT(r->fp_ports),
                    &r->msix_bar,
                    ROCKER_PCI_MSIX_BAR_IDX, ROCKER_PCI_MSIX_TABLE_OFFSET,
                    &r->msix_bar,
                    ROCKER_PCI_MSIX_BAR_IDX, ROCKER_PCI_MSIX_PBA_OFFSET,
                    0);
    if (err)
        return err;

    err = rocker_msix_vectors_use(r, ROCKER_MSIX_VEC_COUNT(r->fp_ports));
    if (err)
        goto err_msix_vectors_use;

    return 0;

err_msix_vectors_use:
    msix_uninit(dev, &r->msix_bar, &r->msix_bar);
    return err;
}

static void rocker_msix_uninit(struct rocker *r)
{
    PCIDevice *dev = PCI_DEVICE(r);

    msix_uninit(dev, &r->msix_bar, &r->msix_bar);
    rocker_msix_vectors_unuse(r, ROCKER_MSIX_VEC_COUNT(r->fp_ports));
}

static int pci_rocker_init(PCIDevice *dev)
{
    struct rocker *r = to_rocker(dev);
    const MACAddr zero = { .a = { 0,0,0,0,0,0 } };
    const MACAddr dflt = { .a = { 0x52, 0x54, 0x00, 0x12, 0x35, 0x01 } };
    static int sw_index = 0;
    int i, err = 0;

    /* allocate worlds */

    r->worlds[ROCKER_WORLD_TYPE_FLOW] = flow_world_alloc(r);
    r->worlds[ROCKER_WORLD_TYPE_L2L3] = l2l3_world_alloc(r);
    r->world_dflt = r->worlds[ROCKER_WORLD_TYPE_L2L3];

    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (!r->worlds[i])
            goto err_world_alloc;

    /* set up memory-mapped region at BAR0 */

    memory_region_init_io(&r->mmio, OBJECT(r), &rocker_mmio_ops, r,
                          "rocker-mmio", ROCKER_PCI_BAR0_SIZE);
    pci_register_bar(dev, ROCKER_PCI_BAR0_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &r->mmio);

    /* set up memory-mapped region for MSI-X */

    memory_region_init(&r->msix_bar, OBJECT(r), "rocker-msix-bar",
                       ROCKER_PCI_MSIX_BAR_SIZE);
    pci_register_bar(dev, ROCKER_PCI_MSIX_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &r->msix_bar);

    /* MSI-X init */

    err = rocker_msix_init(r);
    if (err)
        goto err_msix_init;

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

    if (r->fp_ports > ROCKER_FP_PORTS_MAX)
        r->fp_ports = ROCKER_FP_PORTS_MAX;

    r->rings = g_malloc(sizeof(struct desc_ring *) * rocker_pci_ring_count(r));
    if (!r->rings)
        goto err_rings_alloc;

    /* Rings are ordered like this:
     * - command ring
     * - event ring
     * - port0 tx ring
     * - port0 rx ring
     * - port1 tx ring
     * - port1 rx ring
     * .....
     */

    for (i = 0; i < rocker_pci_ring_count(r); i++) {
        struct desc_ring *ring = desc_ring_alloc(r, i);

        if (!ring)
            goto err_ring_alloc;
        if (i == 0)
            desc_ring_set_consume(ring, cmd_consume, ROCKER_MSIX_VEC_CMD);
        else if (i % 2 == 0)
            desc_ring_set_consume(ring, tx_consume, ROCKER_MSIX_VEC_TX((i - 2) / 2));
        r->rings[i] = ring;
    }

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port =
            fp_port_alloc(r, r->name, &r->fp_start_macaddr,
                          i, &r->fp_ports_peers[i],
                          object_get_typename(OBJECT(r)));

        if (!port)
            goto err_port_alloc;

        r->fp_port[i] = port;
        fp_port_set_world(port, r->world_dflt);
    }

    return 0;

err_port_alloc:
    for (--i; i >= 0; i--) {
        struct fp_port *port = r->fp_port[i];
        fp_port_free(port);
    }
    i = rocker_pci_ring_count(r);
err_ring_alloc:
    for (--i; i >= 0; i--)
        desc_ring_free(r->rings[i]);
    g_free(r->rings);
err_rings_alloc:
    rocker_msix_uninit(r);
err_msix_init:
    memory_region_destroy(&r->msix_bar);
    memory_region_destroy(&r->mmio);
err_world_alloc:
    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (r->worlds[i])
            world_free(r->worlds[i]);

    return err;
}

static void pci_rocker_uninit(PCIDevice *dev)
{
    struct rocker *r = to_rocker(dev);
    int i;

    for (i = 0; i < r->fp_ports; i++) {
        struct fp_port *port = r->fp_port[i];

        fp_port_free(port);
        r->fp_port[i] = NULL;
    }

    for (i = 0; i < rocker_pci_ring_count(r); i++)
        if (r->rings[i])
             desc_ring_free(r->rings[i]);
    g_free(r->rings);

    rocker_msix_uninit(r);
    memory_region_destroy(&r->msix_bar);
    memory_region_destroy(&r->mmio);

    for (i = 0; i < ROCKER_WORLD_TYPE_MAX; i++)
        if (r->worlds[i])
            world_free(r->worlds[i]);
    g_free(r->fp_ports_peers);
}

static void rocker_reset(DeviceState *dev)
{
    struct rocker *r = to_rocker(dev);
    int i;

    for (i = 0; i < r->fp_ports; i++) {
        fp_port_reset(r->fp_port[i]);
        fp_port_set_world(r->fp_port[i], r->world_dflt);
    }

    r->test_reg = 0;
    r->test_reg64 = 0;
    r->test_dma_addr = 0;
    r->test_dma_size = 0;

    for (i = 0; i < rocker_pci_ring_count(r); i++)
        desc_ring_reset(r->rings[i]);

    DPRINTF("Reset done\n");
}

static Property rocker_properties[] = {
    DEFINE_PROP_STRING("name", struct rocker, name),
    DEFINE_PROP_MACADDR("fp_start_macaddr", struct rocker,
                        fp_start_macaddr),
    DEFINE_PROP_UINT64("switch_id", struct rocker,
                       switch_id, 0),
    DEFINE_PROP_ARRAY("ports", struct rocker, fp_ports,
                      fp_ports_peers, qdev_prop_netdev, NICPeers),
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
