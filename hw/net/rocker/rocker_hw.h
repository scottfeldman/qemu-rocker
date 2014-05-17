/*
 * Rocker switch hardware register and descriptor definitions.
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@cumulusnetworks.com>
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
 *
 */

#ifndef _ROCKER_HW_
#define _ROCKER_HW_

#define __le16 uint16_t
#define __le32 uint32_t
#define __le64 uint64_t

/*
 * PCI configuration space
 */

#define ROCKER_PCI_REVISION             0x1
#define ROCKER_PCI_INTERRUPT_PIN        1 /* interrupt pin A */
#define ROCKER_PCI_BAR0_SIZE            0x1000

/*
 * Rocker bogus registers
 */
#define ROCKER_BOGUS_REG0               0x0000
#define ROCKER_BOGUS_REG1               0x0004
#define ROCKER_BOGUS_REG2               0x0008
#define ROCKER_BOGUS_REG3               0x000c

/*
 * Rocker test registers
 */
#define ROCKER_TEST_REG                 0x0010
#define ROCKER_TEST_REG64               0x0018  /* 8-byte */
#define ROCKER_TEST_IRQ                 0x0020
#define ROCKER_TEST_DMA_ADDR            0x0028  /* 8-byte */
#define ROCKER_TEST_DMA_SIZE            0x0030
#define ROCKER_TEST_DMA_CTRL            0x0034

/*
 * Rocker test register ctrl
 */
#define ROCKER_TEST_DMA_CTRL_CLEAR      (1 << 0)
#define ROCKER_TEST_DMA_CTRL_FILL       (1 << 1)
#define ROCKER_TEST_DMA_CTRL_INVERT     (1 << 2)

/*
 * Rocker IRQ registers
 */
#define ROCKER_IRQ_MASK                 0x0200
#define ROCKER_IRQ_STAT                 0x0204

/*
 * Rocker IRQ status bits
 */
#define ROCKER_IRQ_LINK                 (1 << 0)
#define ROCKER_IRQ_TX_DMA_DONE          (1 << 1)
#define ROCKER_IRQ_RX_DMA_DONE          (1 << 2)
#define ROCKER_IRQ_CMD_DMA_DONE         (1 << 3)
#define ROCKER_IRQ_EVENT_DMA_DONE       (1 << 4)
#define ROCKER_IRQ_TEST_DMA_DONE        (1 << 5)

/*
 * Rocker DMA ring register offsets
 */
#define __ROCKER_DMA_DESC_ADDR(x)       (0x0100 + (x) * 32)     /* 8-byte */
#define __ROCKER_DMA_DESC_SIZE(x)       (0x0108 + (x) * 32)
#define __ROCKER_DMA_DESC_HEAD(x)       (0x010c + (x) * 32)
#define __ROCKER_DMA_DESC_TAIL(x)       (0x0110 + (x) * 32)
#define __ROCKER_DMA_DESC_CTRL(x)       (0x0114 + (x) * 32)
#define __ROCKER_DMA_DESC_RSVD1(x)      (0x0118 + (x) * 32)
#define __ROCKER_DMA_DESC_RSVD2(x)      (0x011c + (x) * 32)

#define ROCKER_DMA_RING_REG_SET(name, index)                                    \
enum {                                                                          \
        ROCKER_ ## name ## _DMA_DESC_ADDR = __ROCKER_DMA_DESC_ADDR(index),      \
        ROCKER_ ## name ## _DMA_DESC_SIZE = __ROCKER_DMA_DESC_SIZE(index),      \
        ROCKER_ ## name ## _DMA_DESC_HEAD = __ROCKER_DMA_DESC_HEAD(index),      \
        ROCKER_ ## name ## _DMA_DESC_TAIL = __ROCKER_DMA_DESC_TAIL(index),      \
        ROCKER_ ## name ## _DMA_DESC_CTRL = __ROCKER_DMA_DESC_CTRL(index),      \
        ROCKER_ ## name ## _DMA_DESC_RSVD1 = __ROCKER_DMA_DESC_RSVD1(index),    \
        ROCKER_ ## name ## _DMA_DESC_RSVD2 = __ROCKER_DMA_DESC_RSVD2(index),    \
};\
enum {\
        ROCKER_ ## name ## _INDEX = index,  \
}

ROCKER_DMA_RING_REG_SET(TX, 0);
ROCKER_DMA_RING_REG_SET(RX, 1);
ROCKER_DMA_RING_REG_SET(CMD, 2);
ROCKER_DMA_RING_REG_SET(EVENT, 3);

/*
 * Helper macro to do convert a dma ring register 
 * to its index.  Based on the fact that the register
 * group stride is 32 bytes.
 */
#define ROCKER_RING_INDEX(reg) ((reg >> 5) & 0x7)

/*
 * Rocker DMA Descriptor
 */

struct rocker_desc {
    __le64 buf_addr;
    uint64_t cookie;
    __le16 buf_size;
    __le16 tlv_size;
    __le16 resv[5];   /* pad to 32 bytes */
    __le16 comp_err;
} __attribute__((packed, aligned (8)));

/*
 * Rocker TLV type fields
 */

struct rocker_tlv {
    __le32 type;
    __le16 len;
    __le16 rsvd;
} __attribute__((packed, aligned (8)));

/* cmd msg */
enum {
    ROCKER_TLV_CMD_UNSPEC,
    ROCKER_TLV_CMD_TYPE,                /* u16 */
    ROCKER_TLV_CMD_INFO,                /* nest */

    __ROCKER_TLV_CMD_MAX,
    ROCKER_TLV_CMD_MAX = __ROCKER_TLV_CMD_MAX - 1,
};

enum {
    ROCKER_TLV_CMD_TYPE_UNSPEC,
    ROCKER_TLV_CMD_TYPE_GET_PORT_SETTINGS,
    ROCKER_TLV_CMD_TYPE_SET_PORT_SETTINGS,
    ROCKER_TLV_CMD_TYPE_FLOW, /* to be changed to add/del/stat/... */
    ROCKER_TLV_CMD_TYPE_TRUNK, /* to be changed to ... */
    ROCKER_TLV_CMD_TYPE_BRIDGE, /* to be changed to ... */

    __ROCKER_TLV_CMD_TYPE_MAX,
    ROCKER_TLV_CMD_TYPE_MAX = __ROCKER_TLV_CMD_TYPE_MAX - 1,
};

/* cmd info nested for set/get port settings */
enum {
    ROCKER_TLV_CMD_PORT_SETTINGS_UNSPEC,
    ROCKER_TLV_CMD_PORT_SETTINGS_LPORT,         /* u32 */
    ROCKER_TLV_CMD_PORT_SETTINGS_SPEED,         /* u32 */
    ROCKER_TLV_CMD_PORT_SETTINGS_DUPLEX,        /* u8 */
    ROCKER_TLV_CMD_PORT_SETTINGS_AUTONEG,       /* u8 */
    ROCKER_TLV_CMD_PORT_SETTINGS_MACADDR,       /* binary */
    ROCKER_TLV_CMD_PORT_SETTINGS_MODE,          /* u8 */

    __ROCKER_TLV_CMD_PORT_SETTINGS_MAX,
    ROCKER_TLV_CMD_PORT_SETTINGS_MAX = __ROCKER_TLV_CMD_PORT_SETTINGS_MAX - 1,
};

/* Rx msg */
enum {
    ROCKER_TLV_RX_UNSPEC,
    ROCKER_TLV_RX_LPORT,                /* u32 */
    ROCKER_TLV_RX_FLAGS,                /* u16, see RX_FLAGS_ */
    ROCKER_TLV_RX_CSUM,                 /* u16 */
    ROCKER_TLV_RX_PACKET,               /* binary */

    __ROCKER_TLV_RX_MAX,
    ROCKER_TLV_RX_MAX = __ROCKER_TLV_RX_MAX - 1,
};

#define ROCKER_RX_FLAGS_IPV4                    (1 << 0)
#define ROCKER_RX_FLAGS_IPV6                    (1 << 1)
#define ROCKER_RX_FLAGS_CSUM_CALC               (1 << 2)
#define ROCKER_RX_FLAGS_IPV4_CSUM_GOOD          (1 << 3)
#define ROCKER_RX_FLAGS_IP_FRAG                 (1 << 4)
#define ROCKER_RX_FLAGS_TCP                     (1 << 5)
#define ROCKER_RX_FLAGS_UDP                     (1 << 6)
#define ROCKER_RX_FLAGS_TCP_UDP_CSUM_GOOD       (1 << 7)

/* Tx msg */
enum {
    ROCKER_TLV_TX_UNSPEC,
    ROCKER_TLV_TX_LPORT,                /* u32 */
    ROCKER_TLV_TX_OFFLOAD,              /* u8, see TX_OFFLOAD_ */
    ROCKER_TLV_TX_L3_CSUM_OFF,          /* u16 */
    ROCKER_TLV_TX_TSO_MSS,              /* u16 */
    ROCKER_TLV_TX_TSO_HDR_LEN,          /* u16 */
    ROCKER_TLV_TX_FRAGS,                /* array */

    __ROCKER_TLV_TX_MAX,
    ROCKER_TLV_TX_MAX = __ROCKER_TLV_TX_MAX - 1,
};

#define ROCKER_TX_OFFLOAD_NONE          0
#define ROCKER_TX_OFFLOAD_IP_CSUM       1
#define ROCKER_TX_OFFLOAD_TCP_UDP_CSUM  2
#define ROCKER_TX_OFFLOAD_L3_CSUM       3
#define ROCKER_TX_OFFLOAD_TSO           4

#define ROCKER_TX_FRAGS_MAX             16

enum {
    ROCKER_TLV_TX_FRAG_UNSPEC,
    ROCKER_TLV_TX_FRAG,                 /* nest */

    __ROCKER_TLV_TX_FRAG_MAX,
    ROCKER_TLV_TX_FRAG_MAX = __ROCKER_TLV_TX_FRAG_MAX - 1,
};

enum {
    ROCKER_TLV_TX_FRAG_ATTR_UNSPEC,
    ROCKER_TLV_TX_FRAG_ATTR_ADDR,       /* u64 */
    ROCKER_TLV_TX_FRAG_ATTR_LEN,        /* u16 */

    __ROCKER_TLV_TX_FRAG_ATTR_MAX,
    ROCKER_TLV_TX_FRAG_ATTR_MAX = __ROCKER_TLV_TX_FRAG_ATTR_MAX - 1,
};

/*
 * Flow group types
 */

enum flow_group_type {
    GROUP_TYPE_L2_INTERFACE = 0,
    GROUP_TYPE_L2_REWRITE,
    GROUP_TYPE_L3_UCAST,
    GROUP_TYPE_L2_MCAST,
    GROUP_TYPE_L2_FLOOD,
    GROUP_TYPE_L3_INTERFACE,
    GROUP_TYPE_L3_MCAST,
    GROUP_TYPE_L3_ECMP,
    GROUP_TYPE_L2_OVERLAY,
};

/*
 * Flow overlay types
 */

enum flow_overlay_type {
    OVERLAY_TYPE_FLOOD_UCAST = 0,
    OVERLAY_TYPE_FLOOD_MCAST,
    OVERLAY_TYPE_MCAST_UCAST,
    OVERLAY_TYPE_MCAST_MCAST,
};

/*
 * Rocker general purpose registers
 */
#define ROCKER_CONTROL                  0x0300
#define ROCKER_PORT_PHYS_COUNT          0x0304
#define ROCKER_PORT_PHYS_LINK_STATUS    0x0310 /* 8-byte */
#define ROCKER_PORT_PHYS_ENABLE         0x0318 /* 8-byte */
#define ROCKER_SWITCH_ID                0x0320 /* 8-byte */

/*
 * Rocker control bits
 */
#define ROCKER_CONTROL_RESET            (1 << 0)

#endif /* _ROCKER_HW_ */
