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
#define ROCKER_PCI_BAR0_IDX             0
#define ROCKER_PCI_BAR0_SIZE            0x2000
#define ROCKER_PCI_MSIX_BAR_IDX         1
#define ROCKER_PCI_MSIX_BAR_SIZE        0x2000
#define ROCKER_PCI_MSIX_TABLE_OFFSET    0x0000
#define ROCKER_PCI_MSIX_PBA_OFFSET      0x1000

/*
 * MSI-X vectors
 */

enum {
    ROCKER_MSIX_VEC_CMD,
    ROCKER_MSIX_VEC_EVENT,
    ROCKER_MSIX_VEC_TEST,
    ROCKER_MSIX_VEC_RESERVED0,
    __ROCKER_MSIX_VEC_TX,
    __ROCKER_MSIX_VEC_RX,
#define ROCKER_MSIX_VEC_TX(port) \
                (__ROCKER_MSIX_VEC_TX + (port * 2))
#define ROCKER_MSIX_VEC_RX(port) \
                (__ROCKER_MSIX_VEC_RX + (port * 2))
#define ROCKER_MSIX_VEC_COUNT(portcnt) \
                (ROCKER_MSIX_VEC_RX(portcnt) + 1)
};

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
 * Rocker DMA ring register offsets
 */
#define ROCKER_DMA_DESC_BASE            0x1000
#define ROCKER_DMA_DESC_SIZE            32
#define ROCKER_DMA_DESC_MASK            0x1F
#define ROCKER_DMA_DESC_TOTAL_SIZE      (ROCKER_DMA_DESC_SIZE * 64) /* 62 ports + event + cmd */
#define ROCKER_DMA_DESC_ADDR_OFFSET     0x00     /* 8-byte */
#define ROCKER_DMA_DESC_SIZE_OFFSET     0x08
#define ROCKER_DMA_DESC_HEAD_OFFSET     0x0c
#define ROCKER_DMA_DESC_TAIL_OFFSET     0x10
#define ROCKER_DMA_DESC_CTRL_OFFSET     0x14
#define ROCKER_DMA_DESC_CREDITS_OFFSET  0x18
#define ROCKER_DMA_DESC_RSVD_OFFSET     0x1c

/*
 * Rocker dma ctrl register bits
 */
#define ROCKER_DMA_DESC_CTRL_RESET      (1 << 0)

/*
 * Helper macro to do convert a dma ring register
 * to its index.  Based on the fact that the register
 * group stride is 32 bytes.
 */
#define ROCKER_RING_INDEX(reg) ((reg >> 5) & 0x7F)

/*
 * Rocker DMA Descriptor
 */

struct rocker_desc {
    __le64 buf_addr;
    uint64_t cookie;
    __le16 buf_size;
    __le16 tlv_size;
    __le16 rsvd[5];   /* pad to 32 bytes */
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
    ROCKER_TLV_CMD_TYPE_FLOW_ADD,
    ROCKER_TLV_CMD_TYPE_FLOW_MOD,
    ROCKER_TLV_CMD_TYPE_FLOW_DEL,
    ROCKER_TLV_CMD_TYPE_FLOW_GET_STATS,
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

/* event msg */
enum {
    ROCKER_TLV_EVENT_UNSPEC,
    ROCKER_TLV_EVENT_TYPE,              /* u16 */
    ROCKER_TLV_EVENT_INFO,              /* nest */

    __ROCKER_TLV_EVENT_MAX,
    ROCKER_TLV_EVENT_MAX = __ROCKER_TLV_EVENT_MAX - 1,
};

enum {
    ROCKER_TLV_EVENT_TYPE_UNSPEC,
    ROCKER_TLV_EVENT_TYPE_LINK_CHANGED,

    __ROCKER_TLV_EVENT_TYPE_MAX,
    ROCKER_TLV_EVENT_TYPE_MAX = __ROCKER_TLV_EVENT_TYPE_MAX - 1,
};

/* event info nested for link changed */
enum {
    ROCKER_TLV_EVENT_LINK_CHANGED_UNSPEC,
    ROCKER_TLV_EVENT_LINK_CHANGED_LPORT,    /* u32 */
    ROCKER_TLV_EVENT_LINK_CHANGED_LINKUP,   /* u8 */

    __ROCKER_TLV_EVENT_LINK_CHANGED_MAX,
    ROCKER_TLV_EVENT_LINK_CHANGED_MAX = __ROCKER_TLV_EVENT_LINK_CHANGED_MAX - 1,
};

/* Rx msg */
enum {
    ROCKER_TLV_RX_UNSPEC,
    ROCKER_TLV_RX_FLAGS,                /* u16, see RX_FLAGS_ */
    ROCKER_TLV_RX_CSUM,                 /* u16 */
    ROCKER_TLV_RX_FRAG_ADDR,            /* u64 */
    ROCKER_TLV_RX_FRAG_MAX_LEN,         /* u16 */
    ROCKER_TLV_RX_FRAG_LEN,             /* u16 */

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

/* cmd info nested for flow msgs */
enum {
    ROCKER_TLV_FLOW_TBL,                /* u16 */
    ROCKER_TLV_FLOW_PRIORITY,           /* u32 */
    ROCKER_TLV_FLOW_HARDTIME,           /* u32 */
    ROCKER_TLV_FLOW_IDLETIME,           /* u32 */
    ROCKER_TLV_FLOW_COOKIE,             /* u64 */
    ROCKER_TLV_FLOW_IG_PORT,            /* nest */
    ROCKER_TLV_FLOW_VLAN,               /* nest */
    ROCKER_TLV_FLOW_TERM_MAC,           /* nest */
    ROCKER_TLV_FLOW_BRIDGING,           /* nest */
    ROCKER_TLV_FLOW_UNICAST_ROUTING,    /* nest */
    ROCKER_TLV_FLOW_MULTICAST_ROUTING,  /* nest */
    ROCKER_TLV_FLOW_ACL,                /* nest */

    __ROCKER_TLV_FLOW_MAX,
    ROCKER_TLV_FLOW_MAX = __ROCKER_TLV_FLOW_MAX - 1,
};

/* flow_xxx nest */
enum {
    ROCKER_TLV_FLOW_IN_LPORT,           /* u16 */
    ROCKER_TLV_FLOW_IN_LPORT_MASK,      /* u16 */
    ROCKER_TLV_FLOW_OUT_LPORT,          /* u16 */
    ROCKER_TLV_FLOW_GOTO_TBL,           /* u16 */
    ROCKER_TLV_FLOW_GROUP_ID,           /* u32 */
    ROCKER_TLV_FLOW_VLAN_ID,            /* u16 */
    ROCKER_TLV_FLOW_VLAN_ID_MASK,       /* u16 */
    ROCKER_TLV_FLOW_VLAN_PCP,           /* u16 */
    ROCKER_TLV_FLOW_VLAN_PCP_MASK,      /* u16 */
    ROCKER_TLV_FLOW_VLAN_PCP_ACTION,    /* u8 */
    ROCKER_TLV_FLOW_NEW_VLAN_ID,        /* u16 */
    ROCKER_TLV_FLOW_NEW_VLAN_PCP,       /* u8 */
    ROCKER_TLV_FLOW_TUNNEL_ID,          /* u32 */
    ROCKER_TLV_FLOW_TUN_LOG_LPORT,      /* u32 */
    ROCKER_TLV_FLOW_ETHERTYPE,          /* u16 */
    ROCKER_TLV_FLOW_DST_MAC,            /* binary */
    ROCKER_TLV_FLOW_DST_MAC_MASK,       /* binary */
    ROCKER_TLV_FLOW_SRC_MAC,            /* binary */
    ROCKER_TLV_FLOW_SRC_MAC_MASK,       /* binary */
    ROCKER_TLV_FLOW_IP_PROTO,           /* u16 */
    ROCKER_TLV_FLOW_IP_PROTO_MASK,      /* u16 */
    ROCKER_TLV_FLOW_DSCP,               /* u16 */
    ROCKER_TLV_FLOW_DSCP_MASK,          /* u16 */
    ROCKER_TLV_FLOW_DSCP_ACTION,        /* u8 */
    ROCKER_TLV_FLOW_NEW_DSCP,           /* u8 */
    ROCKER_TLV_FLOW_ECN,                /* u16 */
    ROCKER_TLV_FLOW_ECN_MASK,           /* u16 */
    ROCKER_TLV_FLOW_DST_IP,             /* binary */
    ROCKER_TLV_FLOW_DST_IP_MASK,        /* binary */
    ROCKER_TLV_FLOW_SRC_IP,             /* binary */
    ROCKER_TLV_FLOW_SRC_IP_MASK,        /* binary */
    ROCKER_TLV_FLOW_DST_IPV6,           /* binary */
    ROCKER_TLV_FLOW_DST_IPV6_MASK,      /* binary */
    ROCKER_TLV_FLOW_SRC_IPV6,           /* binary */
    ROCKER_TLV_FLOW_SRC_IPV6_MASK,      /* binary */
    ROCKER_TLV_FLOW_SRC_ARP_IP,         /* u32 */
    ROCKER_TLV_FLOW_SRC_ARP_IP_MASK,    /* u32 */
    ROCKER_TLV_FLOW_L4_DST_PORT,        /* u16 */
    ROCKER_TLV_FLOW_L4_DST_PORT_MASK,   /* u16 */
    ROCKER_TLV_FLOW_L4_SRC_PORT,        /* u16 */
    ROCKER_TLV_FLOW_L4_SRC_PORT_MASK,   /* u16 */
    ROCKER_TLV_FLOW_ICMP_TYPE,          /* u8 */
    ROCKER_TLV_FLOW_ICMP_TYPE_MASK,     /* u8 */
    ROCKER_TLV_FLOW_ICMP_CODE,          /* u8 */
    ROCKER_TLV_FLOW_ICMP_CODE_MASK,     /* u8 */
    ROCKER_TLV_FLOW_IPV6_LABEL,         /* u32 */
    ROCKER_TLV_FLOW_IPV6_LABEL_MASK,    /* u32 */
    ROCKER_TLV_FLOW_QUEUE_ID_ACTION,    /* u8 */
    ROCKER_TLV_FLOW_NEW_QUEUE_ID,       /* u8 */
    ROCKER_TLV_FLOW_CLEAR_ACTIONS,      /* u32 */

    __ROCKER_TLV_FLOW_INFO_MAX,
    ROCKER_TLV_FLOW_INFO_MAX = __ROCKER_TLV_FLOW_INFO_MAX - 1,
};

/* flow stats */
enum {
    ROCKER_TLV_FLOW_STAT_DURATION,      /* u32 */
    ROCKER_TLV_FLOW_STAT_RX_PKTS,       /* u64 */
    ROCKER_TLV_FLOW_STAT_TX_PKTS,       /* u64 */

    __ROCKER_TLV_FLOW_STAT_MAX,
    ROCKER_TLV_FLOW_STAT_MAX = __ROCKER_TLV_FLOW_STAT_MAX - 1,
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
