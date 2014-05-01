/*
 * QEMU rocker switch emulation - flow processing support
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

#include "net/net.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_flow.h"

enum hash_tbl_id {
    HASH_TBL_FLOW_ALL = 0,
    HASH_TBL_FLOW_IG_PORT,
    HASH_TBL_FLOW_VLAN,
    HASH_TBL_FLOW_TERM_MAC,
    HASH_TBL_FLOW_BRIDGING,
    HASH_TBL_FLOW_UNICAST,
    HASH_TBL_FLOW_MULTICAST,
    HASH_TBL_FLOW_ACL,
    HASH_TBL_GROUP_ALL,
    HASH_TABLE_MAX,
};

struct hash_tbl {
    GHashTable *tbl;
    GHashFunc hash_fn;
    GEqualFunc equal_fn;
};

struct flow_world {
    struct hash_tbl hash_tbl[HASH_TABLE_MAX];
};

enum flow_tbl_id {
    FLOW_TABLE_INGRESS_PORT = 0,
    FLOW_TABLE_VLAN = 10,
    FLOW_TABLE_TERMINATION_MAC = 20,
    FLOW_TABLE_UNICAST_ROUTING = 30,
    FLOW_TABLE_MULTICAST_ROUTING = 40,
    FLOW_TABLE_BRIDGING = 50,
    FLOW_TABLE_ACL_POLICY = 60,
};

/* flow_key stolen from OVS */

struct flow_key {
    struct {
        uint32_t priority;           /* flow priority */
        uint16_t in_port;            /* ingress port */
    } phy;
    struct {
        MACAddr src;                 /* ethernet source address */
        MACAddr dst;                 /* ethernet destination address */
        uint16_t tci;                /* 0 if no VLAN */
        uint16_t type;               /* ethernet frame type */
    } eth;
    struct {
        uint8_t proto;               /* IP protocol or ARP opcode */
        uint8_t tos;                 /* IP ToS */
        uint8_t ttl;                 /* IP TTL/hop limit */
        uint8_t frag;                /* one of FRAG_TYPE_* */
    } ip;
    union {
        struct {
            struct {
                uint32_t src;        /* IP source address */
                uint32_t dst;        /* IP destination address */
            } addr;
            union {
                struct {
                    uint16_t src;    /* TCP/UDP/SCTP source port */
                    uint16_t dst;    /* TCP/UDP/SCTP destination port */
                    uint16_t flags;  /* TCP flags */
                } tp;
                struct {
                    MACAddr sha;     /* ARP source hardware address */
                    MACAddr tha;     /* ARP target hardware address */
                } arp;
            };
        } ipv4;
        struct {
            struct {
                uint64_t src[2];     /* IPv6 source address */
                uint64_t dst[2];     /* IPv6 destination address */
            } addr;
            uint32_t label;          /* IPv6 flow label */
            struct {
                uint16_t src;        /* TCP/UDP/SCTP source port */
                uint16_t dst;        /* TCP/UDP/SCTP destination port */
                uint16_t flags;      /* TCP flags */
            } tp;
            struct {
                uint64_t target[2];  /* ND target address */
                MACAddr sll;         /* ND source link layer address */
                MACAddr tll;         /* ND target link layer address */
            } nd;
        } ipv6;
    };
} __attribute__((packed, aligned (8)));

static struct flow_tbl {
    int max_size;
    enum hash_tbl_id hash_tbl_id;
} flow_tbls[] = {
    [FLOW_TABLE_INGRESS_PORT] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_IG_PORT,
    },
    [FLOW_TABLE_VLAN] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_VLAN,
    },
    [FLOW_TABLE_TERMINATION_MAC] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_TERM_MAC,
    },
    [FLOW_TABLE_UNICAST_ROUTING] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_UNICAST,
    },
    [FLOW_TABLE_MULTICAST_ROUTING] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_MULTICAST,
    },
    [FLOW_TABLE_BRIDGING] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_BRIDGING,
    },
    [FLOW_TABLE_ACL_POLICY] = {
        .max_size = 128,
        .hash_tbl_id = HASH_TBL_FLOW_ACL,
    },
};

struct flow {
    struct flow_world *fw;
    struct flow_tbl *tbl;
    GHashTable *hash_all;   /* all flows, key: flow->cookie */
    GHashTable *hash_type;  /* all flows by tbl id, key: flow->cookie */
    enum flow_tbl_id tbl_id;
    uint32_t priority;
    uint32_t hardtime;
    uint32_t idletime;
    uint64_t cookie;
    union {
        struct flow_ig_port {
            uint32_t in_port;
            enum flow_tbl_id goto_tbl;
        } ig_port;
        struct flow_vlan {
            uint32_t in_port;
            uint16_t vlan_id;
            uint16_t vlan_id_mask;
            uint16_t vlan_id_new;
            enum flow_tbl_id goto_tbl;
        } vlan;
        struct flow_term_mac {
            uint32_t in_port;
            uint32_t in_port_mask;
            uint16_t ethertype;
            MACAddr dst_mac;
            MACAddr dst_mac_mask;
            uint16_t vlan_id;
            uint16_t vlan_id_mask;
            enum flow_tbl_id goto_tbl;
            uint32_t out_port;
        } term_mac;
        struct flow_bridging {
            uint16_t vlan_id;
            uint32_t tunnel_id;
            MACAddr dst_mac;
            MACAddr dst_mac_mask;
            enum flow_tbl_id goto_tbl;
            uint32_t group_id;
            uint32_t tun_logical_port;
            uint32_t out_port;
        } bridging;
        struct flow_unicast {
            uint16_t ethertype;
            uint32_t dst_ip;
            uint32_t dst_ip_mask;
            uint64_t dst_ipv6[2];
            uint64_t dst_ipv6_mask[2];
            enum flow_tbl_id goto_tbl;
            uint32_t group_id;
        } unicast;
        struct flow_multicast {
            uint16_t ethertype;
            uint16_t vlan_id;
            uint32_t src_ip;
            uint32_t src_ip_mask;
            uint32_t dst_ip;
            uint64_t src_ipv6[2];
            uint64_t src_ipv6_mask[2];
            uint64_t dst_ipv6[2];
            enum flow_tbl_id goto_tbl;
            uint32_t group_id;
        } multicast;
        struct flow_acl {
            uint32_t in_port;
            uint32_t in_port_mask;
            uint16_t ethertype;
            uint16_t vlan_id;
            uint16_t vlan_id_mask;
            uint16_t vlan_pcp;
            uint16_t vlan_pcp_mask;
            MACAddr src_mac;
            MACAddr src_mac_mask;
            MACAddr dst_mac;
            MACAddr dst_mac_mask;
            uint32_t tunnel_id;
            uint32_t src_ip;
            uint32_t src_ip_mask;
            uint32_t dst_ip;
            uint32_t dst_ip_mask;
            uint64_t src_ipv6[2];
            uint64_t src_ipv6_mask[2];
            uint64_t dst_ipv6[2];
            uint64_t dst_ipv6_mask[2];
            uint32_t src_arp_ip;
            uint32_t src_arp_ip_mask;
            uint16_t ip_proto;
            uint16_t ip_proto_mask;
            uint16_t dscp;
            uint16_t dscp_mask;
            uint16_t ecn;
            uint16_t ecn_mask;
            uint32_t l4_src_port;
            uint32_t l4_src_port_mask;
            uint32_t l4_dst_port;
            uint32_t l4_dst_port_mask;
            uint8_t icmp_type;
            uint8_t icmp_type_mask;
            uint8_t icmp_code;
            uint8_t icmp_code_mask;
            uint32_t ipv6_label;
            uint32_t ipv6_label_mask;
            uint32_t group_id;
            uint8_t queue_id_action;
            uint8_t new_queue_id;
            uint8_t vlan_pcp_action;
            uint8_t new_vlan_pcp;
            uint8_t dscp_action;
            uint8_t new_dscp;
            uint32_t tun_logical_port;
            uint32_t out_port;
            uint32_t clear_actions;
        } acl;
    };
};

int flow_ig(struct fp_port *port, const struct iovec *iov, int iovcnt)
{
    size_t size = iov_size(iov, iovcnt);
    // XXX get flow world from port

    // XXX fun starts here...steps are (roughly):
    // XXX   1) parse pkt to find all match fields (~12 of them)
    // XXX   2) start on flow table 0
    // XXX       a) find table match, if none ???
    // XXX       b) apply actions/group and or repeat 2) on goto table
    // XXX       c) if done, egress pkt to CPU, port, or drop

    return size;
}

static bool flow_tbl_exists(enum flow_tbl_id tbl_id)
{
    switch (tbl_id) {
    case FLOW_TABLE_INGRESS_PORT:
    case FLOW_TABLE_VLAN:
    case FLOW_TABLE_TERMINATION_MAC:
    case FLOW_TABLE_UNICAST_ROUTING:
    case FLOW_TABLE_MULTICAST_ROUTING:
    case FLOW_TABLE_BRIDGING:
    case FLOW_TABLE_ACL_POLICY:
        return true;
    default:
        return false;
    }
}

static bool flow_tbl_full(struct flow *flow)
{
    return g_hash_table_size(flow->hash_type) >= flow->tbl->max_size;
}

static struct flow *flow_find(struct flow_world *fw, uint64_t cookie)
{
    return g_hash_table_lookup(fw->hash_tbl[HASH_TBL_FLOW_ALL].tbl, &cookie);
}

static int flow_add(struct flow *flow)
{
    if (flow_tbl_full(flow))
        return -ENOSPC;

    if (flow_find(flow->fw, flow->cookie))
        return -EEXIST;

    /* validate inputs */
    switch (flow->tbl_id) {
    case FLOW_TABLE_INGRESS_PORT:
    case FLOW_TABLE_VLAN:
    case FLOW_TABLE_TERMINATION_MAC:
    case FLOW_TABLE_UNICAST_ROUTING:
    case FLOW_TABLE_MULTICAST_ROUTING:
    case FLOW_TABLE_BRIDGING:
    case FLOW_TABLE_ACL_POLICY:
        // XXX
        break;
    }

    /*
     * flow gets added to two hash tables:
     *    1) all-flows hash table
     *    2) flow table specific hash table
     */

    g_hash_table_insert(flow->hash_all, &flow->cookie, flow);
    g_hash_table_insert(flow->hash_type, &flow->cookie, flow);

    return 0;
}

static int flow_mod(struct flow *flow)
{
    struct flow *old_flow = flow_find(flow->fw, flow->cookie);

    if (!old_flow)
        return -ENOENT;

    // XXX

    return 0;
}

static int flow_del(struct flow_world *fw, uint64_t cookie)
{
    struct flow *flow = flow_find(fw, cookie);

    if (!flow)
        return -ENOENT;

    g_hash_table_remove(flow->hash_all, &flow->cookie);
    g_hash_table_remove(flow->hash_type, &flow->cookie);

    return 0;
}

static int flow_get_stats(struct flow_world *fw, uint64_t cookie)
{
    struct flow *flow = flow_find(fw, cookie);

    if (!flow)
        return -ENOENT;

    // XXX get/return stats

    return 0;
}

static struct flow *flow_alloc(struct flow_world *fw, enum flow_tbl_id tbl_id)
{
    struct flow *flow;

    if (!flow_tbl_exists(tbl_id))
        return NULL;

    flow = g_malloc0(sizeof(struct flow));
    if (!flow)
        return NULL;

    flow->fw = fw;
    flow->tbl_id = tbl_id;
    flow->tbl = &flow_tbls[tbl_id];
    flow->hash_all = fw->hash_tbl[HASH_TBL_FLOW_ALL].tbl;
    flow->hash_type = fw->hash_tbl[flow->tbl->hash_tbl_id].tbl;

    return flow;
}

static void flow_free(struct flow *flow)
{
    g_free(flow);
}

struct group {
    struct flow_world *fw;
    GHashTable *hash_all;   /* all groups, key = group->id */
    int ref_count;
    uint16_t id;
    enum flow_group_type type;
    uint16_t vlan_id;
    uint16_t l2_port;
    uint32_t index;
    uint8_t overlay_type;
    struct group_action {
        uint16_t next_id;
        uint16_t out_port;
        uint8_t pop_vlan_tag;
        uint16_t vlan_id;
        MACAddr src_mac;
        MACAddr dst_mac;
    } action;
};

static bool group_tbl_full(struct group *group)
{
    // XXX specify group table max size someplace
    return g_hash_table_size(group->hash_all) >= 100;
}

static struct group *group_find(struct flow_world *fw, uint16_t id)
{
    return g_hash_table_lookup(fw->hash_tbl[HASH_TBL_GROUP_ALL].tbl, &id);
}

static int group_add(struct group *group)
{
    struct group *next = group_find(group->fw, group->action.next_id);

    if (group_tbl_full(group))
        return -ENOSPC;

    if (group_find(group->fw, group->id))
        return -EEXIST;

    /* group's action next group can't be self */
    if (next == group)
        return -EINVAL;

    /* group's action next group must exist */
    if (group->type != GROUP_TYPE_L2_INTERFACE &&
        group->action.next_id && !next)
        return -ENODEV;

    /* validate inputs per type */
    switch (group->type) {
    case GROUP_TYPE_L2_INTERFACE:
    case GROUP_TYPE_L2_REWRITE:
    case GROUP_TYPE_L3_UCAST:
    case GROUP_TYPE_L2_MCAST:
    case GROUP_TYPE_L2_FLOOD:
    case GROUP_TYPE_L3_INTERFACE:
    case GROUP_TYPE_L3_MCAST:
    case GROUP_TYPE_L3_ECMP:
    case GROUP_TYPE_L2_OVERLAY:
        // XXX
        break;
    }

    g_hash_table_insert(group->hash_all, &group->id, group);

    if (next)
        next->ref_count++;

    return 0;
}

static int group_mod(struct group *group)
{
    struct group *old_group = group_find(group->fw, group->id);

    if (!old_group)
        return -ENOENT;

    // XXX

    return 0;
}

static int group_del(struct flow_world *fw, uint16_t id)
{
    struct group *group = group_find(fw, id);

    if (!group)
        return -ENOENT;

    if (group->ref_count)
        return -EBUSY;

    g_hash_table_remove(group->hash_all, &id);

    return 0;
}

static int group_get_stats(struct flow_world *fw, uint16_t id)
{
    struct group *group = group_find(fw, id);

    if (!group)
        return -ENOENT;

    // XXX get/return stats

    return 0;
}

static struct group *group_alloc(struct flow_world *fw)
{
    struct group *group = g_malloc0(sizeof(struct group));

    if (!group)
        return NULL;

    group->fw = fw;
    group->hash_all = fw->hash_tbl[HASH_TBL_GROUP_ALL].tbl;

    return group;
}

static void group_free(struct group *group)
{
    g_free(group);
}

int flow_cmd(struct flow_world *fw, char *cmd_buf, size_t size)
{
    struct flow *flow;
    struct group *group;

    // XXX process DMA CMD desc for TLV_FLOW_CMD and TLV_FLOW_GROUP_CMDs

    // XXX call some of the static func for flows and groups to
    // XXX silence the compiler

    flow = flow_alloc(fw, FLOW_TABLE_INGRESS_PORT);
    group = group_alloc(fw);

    flow_add(flow);
    flow_mod(flow);
    flow_get_stats(fw, flow->cookie);
    flow_del(fw, flow->cookie);

    group_add(group);
    group_mod(group);
    group_get_stats(fw, group->id);
    group_del(fw, group->id);

    flow_free(flow);
    group_free(group);

    return 0;
}

static struct hash_tbl hash_tbl_dflts[HASH_TABLE_MAX] = {
    [HASH_TBL_FLOW_ALL] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_IG_PORT] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_VLAN] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_TERM_MAC] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_BRIDGING] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_UNICAST] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_MULTICAST] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_FLOW_ACL] = {
        .hash_fn = g_int64_hash,
        .equal_fn = g_int64_equal,
    },
    [HASH_TBL_GROUP_ALL] = {
        .hash_fn = g_int_hash,
        .equal_fn = g_int_equal,
    },
};

struct flow_world *flow_world_alloc(void)
{
    struct flow_world *fw = g_malloc0(sizeof(struct flow_world));
    int i;

    if (!fw)
        return NULL;

    memcpy(fw->hash_tbl, hash_tbl_dflts, sizeof(fw->hash_tbl));

    for (i = 0; i < HASH_TABLE_MAX; i++) {
        struct hash_tbl *hash = &fw->hash_tbl[i];
        hash->tbl = g_hash_table_new(hash->hash_fn, hash->equal_fn);
        if (!hash->tbl)
            goto err_hash_table_new;
    }

    return fw;

err_hash_table_new:
    for (i--; i >= 0; i--)
        g_hash_table_destroy(fw->hash_tbl[i].tbl);
    g_free(fw);
    return NULL;
}

void flow_world_free(struct flow_world *fw)
{
    int i;

    for (i = 0; i < HASH_TABLE_MAX; i++)
        g_hash_table_destroy(fw->hash_tbl[i].tbl);
    g_free(fw);
}
