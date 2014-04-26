/*
 * Rocker switch hardware register and descriptor definitions.
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@cumulusnetworks.com>
 *
 * This header file should be sharable between rocker device model
 * in qemu and the rocker Linux kernel driver.  As such, it comforms
 * to the Linux style-guide.
 *
 */

#ifndef _ROCKER_HW_
#define _ROCKER_HW_

/*
 * PCI configuration space
 */

#define ROCKER_PCI_REVISION		0x1

#define ROCKER_PCI_INTERRUPT_PIN	1 /* interrupt pin A */

#define ROCKER_PCI_BAR0_SIZE		0x1000

/*
 * Rocker test registers
 */
#define ROCKER_TEST_REG			0x0010
#define ROCKER_TEST_REG64		0x0018	/* 8-byte */
#define ROCKER_TEST_IRQ			0x0020
#define ROCKER_TEST_DMA_ADDR		0x0028	/* 8-byte */
#define ROCKER_TEST_DMA_SIZE		0x0030
#define ROCKER_TEST_DMA_CTRL		0x0034

/*
 * Rocker test register ctrl
 */
#define TEST_DMA_CTRL_CLEAR		(1 << 0)
#define TEST_DMA_CTRL_FILL		(1 << 1)
#define TEST_DMA_CTRL_INVERT		(1 << 2)

/*
 * Rocker IRQ registers
 */
#define ROCKER_IRQ_MASK			0x0200
#define ROCKER_IRQ_STAT			0x0204

/*
 * Rocker IRQ status bits
 */
#define IRQ_LINK			(1 << 0)
#define IRQ_TX_DMA_DONE			(1 << 1)
#define IRQ_RX_DMA_DONE			(1 << 2)
#define IRQ_CMD_DMA_DONE		(1 << 3)
#define IRQ_EVENT_DMA_DONE		(1 << 4)

/*
 * Rocker DMA ring register offsets
 */
#define DMA_DESC_ADDR(x)		(0x0100 + (x) * 32)	/* 8-byte */
#define DMA_COMP_ADDR(x)		(0x0108 + (x) * 32)	/* 8-byte */
#define DMA_DESC_SIZE(x)		(0x0110 + (x) * 32)
#define DMA_DESC_HEAD(x)		(0x0114 + (x) * 32)
#define DMA_DESC_TAIL(x)		(0x0118 + (x) * 32)
#define DMA_DESC_CTRL(x)		(0x011c + (x) * 32)

#define ROCKER_DMA_RING_REG_SET(name, index) \
enum {\
	name ## _DMA_DESC_ADDR = DMA_DESC_ADDR(index),\
	name ## _DMA_COMP_ADDR = DMA_COMP_ADDR(index),\
	name ## _DMA_DESC_SIZE = DMA_DESC_SIZE(index),\
	name ## _DMA_DESC_HEAD = DMA_DESC_HEAD(index),\
	name ## _DMA_DESC_TAIL = DMA_DESC_TAIL(index),\
	name ## _DMA_DESC_CTRL = DMA_DESC_CTRL(index),\
}

ROCKER_DMA_RING_REG_SET(TX, 0);
ROCKER_DMA_RING_REG_SET(RX, 1);
ROCKER_DMA_RING_REG_SET(CMD, 2);
ROCKER_DMA_RING_REG_SET(EVENT, 3);

/*
 * Rocker DMA Descriptor and completion structs
 */
struct rocker_dma_tlv {
	uint32_t type;
	uint16_t len;
} __attribute__((packed, aligned (8)));

struct rocker_dma_desc {
	uint64_t buf_addr;
	uint64_t cookie;
	uint16_t buf_size;
	uint16_t tlv_size;
} __attribute__((packed, aligned (8)));

struct rocker_comp_desc {
	uint64_t cookie_gen;
	uint16_t tlv_size;
	uint16_t comp_status;
} __attribute__((packed, aligned(8)));

/*
 * Rocker TLV type fields
 */

enum {
	/* Nest type */
	TLV_NEST		= 1,
	/* TX TLV's */
	TLV_LPORT,
	TLV_TX_OFFLOADS,
	TLV_L3_CSUM_OFF,
	TLV_TX_FRAG_CNT,
	TLV_TX_FRAG,

	/* Flow Table TLV's */
	TLV_FLOW_CMD,
	TLV_FLOW_TBL,
	TLV_FLOW_PRIO,
	TLV_FLOW_HARDT,
	TLV_FLOW_IDLET,
	TLV_FLOW_COOKIE,
	TLV_FLOW_IN_PORT,
	TLV_FLOW_VLAN_ID,
	TLV_FLOW_VLAN_IS_MASK,
	TLV_FLOW_NEW_VLAN_ID,
	TLV_FLOW_TUNNEL_ID,
	TLV_FLOW_DST_MAC,
	TLV_FLOW_DST_MAC_MASK,
	TLV_FLOW_GROUP_ID,
	TLV_FLOW_TUN_LOG_PORT,
	TLV_FLOW_OUT_PORT,
	TLV_FLOW_ETHTYPE,
	TLV_FLOW_DST_IP,
	TLV_FLOW_DST_IP_MASK,
	TLV_FLOW_DST_IPV6,
	TLV_FLOW_DST_IPV6_MASK,
	TLV_FLOW_SRC_IP,
	TLV_FLOW_SRC_IP_MASK,
	TLV_FLOW_SRC_IPV6,
	TLV_FLOW_SRC_IPV6_MASK,
	TLV_FLOW_STAT_DURATION,
	TLV_FLOW_STAT_RX_PKT,
	TLV_FLOW_STAT_TX_PKT,

	/* Trunking TLV's */
	TLV_TRUNK_CMD,
	TLV_TRUNK_LPORT,
	TLV_TRUNK_HASH,
	TLV_TRUNK_MEMBER,
	TLV_TRUNK_ACTIVE,

	/* Bridging TLV's */
	TLV_BRIDGE_CMD,
	TLV_BRIDGE_LPORT,
	TLV_BRIDGE_MEMBER,

	/* Nested TLVs */
	TLV_FLOW_IG_PORT	= TLV_NEST,
	TLV_FLOW_VLAN		= TLV_NEST,
	TLV_FLOW_BRIDGNIG	= TLV_NEST,
	TLV_FLOW_UCAST_RT	= TLV_NEST,
	TLV_FLOW_MCAST_RT	= TLV_NEST,
};

/*
 * Command TLV value definitions
 */
#define CMD_ADD		0
#define CMD_DEL		1
#define CMD_MOD		2
#define CMD_GET_STATS	3

/*
 * Rocker general purpose registers
 */
#define ROCKER_ENDIANESS_SEL		0x0300
#define ROCKER_PORT_PHYS_COUNT		0x0304
#define ROCKER_PORT_PHYS_MODE		0x0308	/* 8-byte */
#define ROCKER_PORT_PHYS_LINK_STATUS	0x0310	/* 8-byte */

#endif /* _ROCKER_HW_ */
