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
#include "net/eth.h"
#include "qemu/iov.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_desc.h"
#include "rocker_flow.h"

struct flow_world {
    struct world *world;
    GHashTable *flow_tbl;
    GHashTable *group_tbl;
    unsigned int flow_tbl_max_size;
    unsigned int group_tbl_max_size;
};

struct group {
    struct flow_world *fw;
    int ref_count;
    uint16_t id;
    enum flow_group_type type;
    __be16 vlan_id;
    uint32_t lport;
    uint32_t index;
    uint8_t overlay_type;
    struct {
        uint16_t next_id;
        uint32_t out_lport;
        uint8_t pop_vlan_tag;
        __be16 vlan_id;
        MACAddr src_mac;
        MACAddr dst_mac;
    } action;
};

static bool group_tbl_full(struct group *group)
{
    return g_hash_table_size(group->fw->group_tbl) >=
        group->fw->group_tbl_max_size;
}

static struct group *group_find(struct flow_world *fw, uint16_t id)
{
    return g_hash_table_lookup(fw->group_tbl, &id);
}

static int group_add(struct group *group)
{
    struct group *next = group_find(group->fw, group->action.next_id);

    if (group_tbl_full(group))
        return -ENOSPC;

    if (group_find(group->fw, group->id))
        return -EEXIST;

    /* group's action next group can't be self */
    if (group->action.next_id == group->id)
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

    g_hash_table_insert(group->fw->group_tbl, &group->id, group);

    if (next)
        next->ref_count++;

    return 0;
}

#if 0
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
#endif

static struct group *group_alloc(struct flow_world *fw)
{
    struct group *group = g_malloc0(sizeof(struct group));

    if (!group)
        return NULL;

    group->fw = fw;

    return group;
}

enum flow_tbl_id {
    FLOW_TABLE_INGRESS_PORT = 0,
    FLOW_TABLE_VLAN = 10,
    FLOW_TABLE_TERMINATION_MAC = 20,
    FLOW_TABLE_UNICAST_ROUTING = 30,
    FLOW_TABLE_MULTICAST_ROUTING = 40,
    FLOW_TABLE_BRIDGING = 50,
    FLOW_TABLE_ACL_POLICY = 60,
};

/* flow_key stolen mostly from OVS
 *
 * Note: fields that compare with network packet header fields
 * are stored in network order (BE) to avoid per-packet field
 * byte-swaps.
 */

struct flow_key {
    uint32_t priority;               /* flow priority */
    uint32_t in_lport;               /* ingress port */
    uint32_t tunnel_id;              /* overlay tunnel id */
    enum flow_tbl_id tbl_id;         /* table id */
    struct {
        __be16 vlan_id;              /* VLAN ID */
        MACAddr src;                 /* ethernet source address */
        MACAddr dst;                 /* ethernet destination address */
        __be16 tci;                  /* 0 if no VLAN */
        __be16 type;                 /* ethernet frame type */
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
                __be32 src;          /* IP source address */
                __be32 dst;          /* IP destination address */
            } addr;
            union {
                struct {
                    __be16 src;      /* TCP/UDP/SCTP source port */
                    __be16 dst;      /* TCP/UDP/SCTP destination port */
                    __be16 flags;    /* TCP flags */
                } tp;
                struct {
                    MACAddr sha;     /* ARP source hardware address */
                    MACAddr tha;     /* ARP target hardware address */
                } arp;
            };
        } ipv4;
        struct {
            struct {
                ipv6_addr src;       /* IPv6 source address */
                ipv6_addr dst;       /* IPv6 destination address */
            } addr;
            __be32 label;            /* IPv6 flow label */
            struct {
                __be16 src;          /* TCP/UDP/SCTP source port */
                __be16 dst;          /* TCP/UDP/SCTP destination port */
                __be16 flags;        /* TCP flags */
            } tp;
            struct {
                ipv6_addr target;    /* ND target address */
                MACAddr sll;         /* ND source link layer address */
                MACAddr tll;         /* ND target link layer address */
            } nd;
        } ipv6;
    };
};

#define FLOW_KEY_WIDTH(f) \
    ((offsetof(struct flow_key, f) / sizeof(uint64_t)) + 1)

struct flow_action {
    enum flow_tbl_id goto_tbl;
    struct {
        uint16_t group_id;
        uint32_t tun_log_lport;
        __be16 vlan_id;
    } write;
    struct {
        __be16 new_vlan_id;
        uint32_t out_lport;
    } apply;
};

struct flow {
    struct flow_world *fw;
    uint32_t priority;
    uint32_t hardtime;
    uint32_t idletime;
    uint64_t cookie;
    struct flow_key key;
    struct flow_key mask;
    struct flow_action action;
    struct {
        uint32_t duration;
        uint64_t rx_pkts;
        uint64_t tx_pkts;
    } stats;
};

static bool flow_tbl_full(struct flow *flow)
{
    return g_hash_table_size(flow->fw->flow_tbl) >= flow->fw->flow_tbl_max_size;
}

static int flow_cmd(struct world *world, struct desc_info *info,
                    char *buf, uint16_t cmd,
                    struct rocker_tlv *cmd_info_tlv)
{
    return g_hash_table_lookup(fw->flow_tbl, &cookie);
}

static int flow_add(struct flow *flow)
{
    if (flow_tbl_full(flow))
        return -ENOSPC;

    g_hash_table_insert(flow->fw->flow_tbl, &flow->cookie, flow);

    return 0;
}

static int flow_mod(struct flow *flow)
{
    return 0;
}

static void flow_del(struct flow *flow)
{
    g_hash_table_remove(flow->fw->flow_tbl, &flow->cookie);
}

static struct flow *flow_alloc(struct flow_world *fw, uint64_t cookie,
                               uint32_t priority, uint32_t hardtime,
                               uint32_t idletime)
{
    struct flow *flow;

    flow = g_malloc0(sizeof(struct flow));
    if (!flow)
        return NULL;

    flow->fw = fw;
    flow->cookie = cookie;
    flow->priority = priority;
    flow->hardtime = hardtime;
    flow->idletime = idletime;

    return flow;
}

struct flow_pkt_fields {
    uint32_t tunnel_id;
    struct eth_header *ethhdr;
    __be16 *h_proto;
    struct vlan_header *vlanhdr;
    struct ip_header *ipv4hdr;
    struct ip6_header *ipv6hdr;
    ipv6_addr *ipv6_src_addr;
    ipv6_addr *ipv6_dst_addr;
};

struct flow_context {
    uint32_t lport;
    uint32_t tunnel_id;
    struct iovec *iov;
    int iovcnt;
    struct vlan_header vlanhdr;
    struct flow_pkt_fields fields;
    struct flow_action action_set;
};

struct flow_match {
    struct flow_key value;
    struct flow *best;
    int width;
};

static void flow_ig_tbl(struct flow_world *fw, struct flow_context *fc,
                        enum flow_tbl_id tbl_id);

static void flow_pkt_parse(struct flow_context *fc,
                           const struct iovec *iov, int iovcnt)
{
    struct flow_pkt_fields *fields = &fc->fields;
    size_t sofar = 0;
    int i;

    sofar += sizeof(struct eth_header);
    if (iov->iov_len < sofar) {
        DPRINTF("flow_pkt_parse underrun on eth_header\n");
        return;
    }

    fields->ethhdr = iov->iov_base;
    fields->h_proto = &fields->ethhdr->h_proto;

    if (ntohs(*fields->h_proto) == ETH_P_VLAN) {
        sofar += sizeof(struct vlan_header);
        if (iov->iov_len < sofar) {
            DPRINTF("flow_pkt_parse underrun on vlan_header\n");
            return;
        }
        fields->vlanhdr = (struct vlan_header *)fields->h_proto;
        fields->h_proto = (__be16 *)(fields->vlanhdr + 1);
    }

    switch (ntohs(*fields->h_proto)) {
    case ETH_P_IP:
        sofar += sizeof(struct ip_header);
        if (iov->iov_len < sofar) {
            DPRINTF("flow_pkt_parse underrun on ip_header\n");
            return;
        }
        fields->ipv4hdr = (struct ip_header *)(fields->h_proto + 1);
        break;
    }

    /* To facilitate (potential) VLAN tag insertion, Make a
     * copy of the iov and insert two new vectors at the
     * beginning for eth hdr and vlan hdr.  No data is copied,
     * just the vectors.
     */

    fc->iov[0].iov_base = fields->ethhdr;
    fc->iov[0].iov_len = ETH_ALEN * 2;

    fc->iov[1].iov_base = fields->vlanhdr;
    fc->iov[1].iov_len = fields->vlanhdr ? sizeof(struct vlan_header) : 0;

    fc->iov[2].iov_base = fields->h_proto;
    fc->iov[2].iov_len = iov->iov_len - fc->iov[0].iov_len - fc->iov[1].iov_len;

    for (i = 1; i < iovcnt; i++)
        fc->iov[i+2] = iov[i];

    fc->iovcnt = iovcnt + 2;
}

static void flow_pkt_insert_vlan(struct flow_context *fc)
{
    struct flow_pkt_fields *fields = &fc->fields;

    if (fields->vlanhdr) {
        DPRINTF("flow_pkt_insert_vlan packet already has outer vlan\n");
        return;
    }

    fields->vlanhdr = &fc->vlanhdr;

    fc->iov[1].iov_base = fields->vlanhdr;
    fc->iov[1].iov_len = sizeof(struct vlan_header);
}

static void flow_pkt_strip_vlan(struct flow_context *fc)
{
    struct flow_pkt_fields *fields = &fc->fields;

    if (!fields->vlanhdr) {
        DPRINTF("flow_pkt_strip_vlan packet has no outer vlan to strip\n");
        return;
    }

    fields->vlanhdr = NULL;

    fc->iov[1].iov_base = fields->vlanhdr;
    fc->iov[1].iov_len = 0;
}

static void flow_exec_action_set(struct flow_world *fw,
                                 struct flow_context *fc)
{
    struct flow_action *set = &fc->action_set;
    struct group *group;

    if (set->write.group_id) {
        group = group_find(fw, set->write.group_id);
        if (!group) {
            DPRINTF("flow_exec_action_set group %d not found\n",
                    set->write.group_id);
            return;
        }
        if (group->action.pop_vlan_tag)
            flow_pkt_strip_vlan(fc);
        rocker_port_eg(world_rocker(fw->world),
                       group->action.out_lport,
                       fc->iov, fc->iovcnt);
    }
}

static void flow_ig_port_build_match(struct flow_context *fc,
                                     struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_INGRESS_PORT;
    match->value.in_lport = fc->lport;
    match->width = FLOW_KEY_WIDTH(tbl_id);
}

static void flow_vlan_build_match(struct flow_context *fc,
                                  struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_VLAN;
    match->value.in_lport = fc->lport;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    match->width = FLOW_KEY_WIDTH(eth.vlan_id);
}

static void flow_vlan_insert(struct flow_context *fc, struct flow *flow)
{
    if (flow->action.apply.new_vlan_id) {
        flow_pkt_insert_vlan(fc);
        fc->fields.vlanhdr->h_proto = htons(ETH_P_VLAN);
        fc->fields.vlanhdr->h_tci = flow->action.apply.new_vlan_id;
    }
}

static void flow_term_mac_build_match(struct flow_context *fc,
                                      struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_TERMINATION_MAC;
    match->value.in_lport = fc->lport;
    match->value.eth.type = *fc->fields.h_proto;
    match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->width = FLOW_KEY_WIDTH(eth.type);
}

static void flow_term_mac_miss(struct flow_world *fw, struct flow_context *fc)
{
    flow_ig_tbl(fw, fc, FLOW_TABLE_BRIDGING);
}

static void flow_copy_to_controller(struct flow_context *fc, struct flow *flow)
{
    if (flow->action.apply.out_lport) {
        // XXX send copy of pkt to controller, out_lport must
        // XXX be controller lport
    }
}

static void flow_bridging_build_match(struct flow_context *fc,
                                      struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_BRIDGING;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    else if (fc->tunnel_id)
        match->value.tunnel_id = fc->tunnel_id;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->width = FLOW_KEY_WIDTH(eth.dst);
}

static void flow_bridging_miss(struct flow_world *fw, struct flow_context *fc)
{
    flow_ig_tbl(fw, fc, FLOW_TABLE_ACL_POLICY);
}

static void flow_bridging_action_write(struct flow_context *fc,
                                       struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.tun_log_lport = flow->action.write.tun_log_lport;
}

static void flow_unicast_routing_build_match(struct flow_context *fc,
                                             struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_UNICAST_ROUTING;
    match->value.eth.type = *fc->fields.h_proto;
    if (fc->fields.ipv4hdr)
        match->value.ipv4.addr.dst = fc->fields.ipv4hdr->ip_dst;
    if (fc->fields.ipv6_dst_addr)
        memcpy(&match->value.ipv6.addr.dst, fc->fields.ipv6_dst_addr,
               sizeof(match->value.ipv6.addr.dst));
    match->width = FLOW_KEY_WIDTH(ipv6.addr.dst);
}

static void flow_unicast_routing_action_write(struct flow_context *fc,
                                              struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
}

static void flow_multicast_routing_build_match(struct flow_context *fc,
                                               struct flow_match *match)
{
    match->value.tbl_id = FLOW_TABLE_MULTICAST_ROUTING;
    match->value.eth.type = *fc->fields.h_proto;
    match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    if (fc->fields.ipv4hdr) {
        match->value.ipv4.addr.src = fc->fields.ipv4hdr->ip_src;
        match->value.ipv4.addr.dst = fc->fields.ipv4hdr->ip_dst;
    }
    if (fc->fields.ipv6_src_addr)
        memcpy(&match->value.ipv6.addr.src, fc->fields.ipv6_src_addr,
               sizeof(match->value.ipv6.addr.src));
    if (fc->fields.ipv6_dst_addr)
        memcpy(&match->value.ipv6.addr.dst, fc->fields.ipv6_dst_addr,
               sizeof(match->value.ipv6.addr.dst));
    match->width = FLOW_KEY_WIDTH(ipv6.addr.dst);
}

static void flow_multicast_routing_action_write(struct flow_context *fc,
                                                struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.vlan_id = flow->action.write.vlan_id;
}

static struct flow_tbl_ops {
    void (*build_match)(struct flow_context *fc, struct flow_match *match);
    void (*miss)(struct flow_world *fw, struct flow_context *fc);
    void (*action_apply)(struct flow_context *fc, struct flow *flow);
    void (*action_write)(struct flow_context *fc, struct flow *flow);
} tbl_ops[] = {
    [FLOW_TABLE_INGRESS_PORT] = {
        .build_match = flow_ig_port_build_match,
    },
    [FLOW_TABLE_VLAN] = {
        .build_match = flow_vlan_build_match,
        .action_apply = flow_vlan_insert,
    },
    [FLOW_TABLE_TERMINATION_MAC] = {
        .build_match = flow_term_mac_build_match,
        .miss = flow_term_mac_miss,
        .action_apply = flow_copy_to_controller,
    },
    [FLOW_TABLE_BRIDGING] = {
        .build_match = flow_bridging_build_match,
        .miss = flow_bridging_miss,
        .action_apply = flow_copy_to_controller,
        .action_write = flow_bridging_action_write,
    },
    [FLOW_TABLE_UNICAST_ROUTING] = {
        .build_match = flow_unicast_routing_build_match,
        .action_write = flow_unicast_routing_action_write,
    },
    [FLOW_TABLE_MULTICAST_ROUTING] = {
        .build_match = flow_multicast_routing_build_match,
        .action_write = flow_multicast_routing_action_write,
    },
    [FLOW_TABLE_ACL_POLICY] = {
        // XXX implement this
    },
};

static void flow_match(void *key, void *value, void *user_data)
{
    struct flow *flow = value;
    struct flow_match *match = user_data;
    uint64_t *k = (uint64_t *)&flow->key;
    uint64_t *m = (uint64_t *)&flow->mask;
    uint64_t *v = (uint64_t *)&match->value;
    int i;

    for (i = 0; i < match->width; i++, k++, m++, v++) {
        DPRINTF("key 0x%016lx mask 0x%016lx value 0x%016lx\n", *k, *m, *v);
        if ((~*k & ~*m & *v) | (*k & ~*m & ~*v)) {
            DPRINTF("no match\n");
            return;
        }
    }
    DPRINTF("match\n");

    if (!match->best || flow->key.priority > match->best->key.priority)
        match->best = flow;
}

static void flow_ig_tbl(struct flow_world *fw, struct flow_context *fc,
                        enum flow_tbl_id tbl_id)
{
    struct flow_tbl_ops *ops = &tbl_ops[tbl_id];
    struct flow_match match = { { 0, }, };
    struct flow *flow;

    if (ops->build_match)
        ops->build_match(fc, &match);
    else
        return;

    g_hash_table_foreach(fw->flow_tbl, flow_match, &match);

    flow = match.best;

    if (!flow) {
        if (ops->miss)
            ops->miss(fw, fc);
        return;
    }

    if (ops->action_apply)
        ops->action_apply(fc, flow);

    if (ops->action_write)
        ops->action_write(fc, flow);

    if (flow->action.goto_tbl)
        flow_ig_tbl(fw, fc, flow->action.goto_tbl);
    else
        flow_exec_action_set(fw, fc);
}

static ssize_t flow_ig(struct world *world, uint32_t lport,
                       const struct iovec *iov, int iovcnt)
{
    struct flow_world *fw = world_private(world);
    struct iovec iov_copy[iovcnt + 2];
    struct flow_context fc = {
        .lport = lport,
        .iov = iov_copy,
        .iovcnt = iovcnt + 2,
    };

    flow_pkt_parse(&fc, iov, iovcnt);
    flow_ig_tbl(fw, &fc, FLOW_TABLE_INGRESS_PORT);

    return iov_size(iov, iovcnt);
}

#define ROCKER_TUNNEL_LPORT 0x00010000

static int flow_cmd_add_ig_port(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_action *action = &flow->action;
    bool overlay_tunnel;

    if (!info[ROCKER_TLV_FLOW_IN_LPORT] ||
        !info[ROCKER_TLV_FLOW_GOTO_TBL])
        return -EINVAL;

    key->tbl_id = FLOW_TABLE_INGRESS_PORT;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_IN_LPORT]);
    overlay_tunnel = !!(key->in_lport & ROCKER_TUNNEL_LPORT);

    action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);

    if (!overlay_tunnel && action->goto_tbl != FLOW_TABLE_VLAN)
        return -EINVAL;

    if (overlay_tunnel && action->goto_tbl != FLOW_TABLE_BRIDGING)
        return -EINVAL;

    return 0;
}

static int flow_cmd_add_vlan(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    bool untagged;

    if (!info[ROCKER_TLV_FLOW_IN_LPORT] ||
        !info[ROCKER_TLV_FLOW_VLAN_ID] ||
        !info[ROCKER_TLV_FLOW_VLAN_ID_MASK] ||
        !info[ROCKER_TLV_FLOW_GOTO_TBL])
        return -EINVAL;

    key->tbl_id = FLOW_TABLE_VLAN;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_IN_LPORT]);
    if (1 < key->in_lport || key->in_lport > 63)
        return -EINVAL;
    mask->in_lport = 0x0000003f;

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID]);
    mask->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID_MASK]);
    if (mask->eth.vlan_id == htons(0x1fff))
        untagged = false; /* filtering */
    else if (mask->eth.vlan_id == htons(0x0fff))
        untagged = true;
    else
        return -EINVAL;

    action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);

    if (action->goto_tbl != FLOW_TABLE_TERMINATION_MAC)
        return -EINVAL;

    if (untagged) {
        if (!info[ROCKER_TLV_FLOW_NEW_VLAN_ID])
            return -EINVAL;
        action->apply.new_vlan_id =
            rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_NEW_VLAN_ID]);
        if (1 < ntohs(action->apply.new_vlan_id) ||
            ntohs(action->apply.new_vlan_id) > 4094)
            return -EINVAL;
    }

    return 0;
}

static int flow_cmd_add_term_mac(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    const MACAddr ipv4_mcast = { .a = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 } };
    const MACAddr ipv4_mask =  { .a = { 0xff, 0xff, 0xff, 0x80, 0x00, 0x00 } };
    const MACAddr ipv6_mcast = { .a = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 } };
    const MACAddr ipv6_mask =  { .a = { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } };
    bool unicast = false;
    bool multicast = false;

    if (!info[ROCKER_TLV_FLOW_IN_LPORT] ||
        !info[ROCKER_TLV_FLOW_IN_LPORT_MASK] ||
        !info[ROCKER_TLV_FLOW_ETHERTYPE] ||
        !info[ROCKER_TLV_FLOW_DST_MAC] ||
        !info[ROCKER_TLV_FLOW_DST_MAC_MASK] ||
        !info[ROCKER_TLV_FLOW_VLAN_ID] ||
        !info[ROCKER_TLV_FLOW_VLAN_ID_MASK])
        return -EINVAL;

    key->tbl_id = FLOW_TABLE_TERMINATION_MAC;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_IN_LPORT]);
    if (1 < key->in_lport || key->in_lport > 63)
        return -EINVAL;
    mask->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_IN_LPORT_MASK]);

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_ETHERTYPE]);
    if (key->eth.type != 0x0800 || key->eth.type != 0x86dd)
        return -EINVAL;

    memcpy(key->eth.dst.a, rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_MAC]),
        sizeof(key->eth.dst.a));
    memcpy(mask->eth.dst.a, rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_MAC_MASK]),
        sizeof(mask->eth.dst.a));

    if ((key->eth.dst.a[5] & 0x01) == 0x00)
        unicast = true;

    /* only two wildcard rules are acceptable for IPv4 and IPv6 multicast */
    if (memcmp(key->eth.dst.a, ipv4_mcast.a, sizeof(key->eth.dst.a)) == 0 &&
        memcmp(mask->eth.dst.a, ipv4_mask.a, sizeof(mask->eth.dst.a)) == 0)
        multicast = true;
    if (memcmp(key->eth.dst.a, ipv6_mcast.a, sizeof(key->eth.dst.a)) == 0 &&
        memcmp(mask->eth.dst.a, ipv6_mask.a, sizeof(mask->eth.dst.a)) == 0)
        multicast = true;

    if (!unicast && !multicast)
        return -EINVAL;

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID]);
    mask->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID_MASK]);

    if (info[ROCKER_TLV_FLOW_GOTO_TBL]) {
        action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);
    
        if (action->goto_tbl != FLOW_TABLE_UNICAST_ROUTING ||
            action->goto_tbl != FLOW_TABLE_MULTICAST_ROUTING)
            return -EINVAL;

        if (unicast && action->goto_tbl != FLOW_TABLE_UNICAST_ROUTING)
            return -EINVAL;

        if (multicast && action->goto_tbl != FLOW_TABLE_MULTICAST_ROUTING)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_OUT_LPORT])
        action->apply.out_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_OUT_LPORT]);

    return 0;
}

static int flow_cmd_add_bridging(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    bool unicast = false;
    bool dst_mac = false;
    bool dst_mac_mask = false;
    enum {
        BRIDGING_MODE_UNKNOWN,
        BRIDGING_MODE_VLAN_UCAST,
        BRIDGING_MODE_VLAN_MCAST,
        BRIDGING_MODE_VLAN_DFLT,
        BRIDGING_MODE_TUNNEL_UCAST,
        BRIDGING_MODE_TUNNEL_MCAST,
        BRIDGING_MODE_TUNNEL_DFLT,
    } mode = BRIDGING_MODE_UNKNOWN;

    key->tbl_id = FLOW_TABLE_BRIDGING;

    if (info[ROCKER_TLV_FLOW_VLAN_ID])
        key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID]);

    if (info[ROCKER_TLV_FLOW_TUNNEL_ID])
        key->tunnel_id = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_TUNNEL_ID]);

    /* can't do VLAN bridging and tunnel bridging at same time */
    if (key->eth.vlan_id && key->tunnel_id)
        return -EINVAL;

    if (info[ROCKER_TLV_FLOW_DST_MAC]) {
        memcpy(key->eth.dst.a, rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_MAC]),
            sizeof(key->eth.dst.a));
        dst_mac = true;
        unicast = (key->eth.dst.a[5] & 0x01) == 0x00;
    }

    if (info[ROCKER_TLV_FLOW_DST_MAC_MASK]) {
        memcpy(mask->eth.dst.a,
               rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_MAC_MASK]),
               sizeof(mask->eth.dst.a));
        dst_mac_mask = true;
    }

    if (key->eth.vlan_id) {
        if (dst_mac && !dst_mac_mask) {
            mode = unicast ? BRIDGING_MODE_VLAN_UCAST :
                             BRIDGING_MODE_VLAN_MCAST;
        } else if ((dst_mac && dst_mac_mask) || !dst_mac) {
            mode = BRIDGING_MODE_VLAN_DFLT;
        }
    } else if (key->tunnel_id) {
        if (dst_mac && !dst_mac_mask) {
            mode = unicast ? BRIDGING_MODE_TUNNEL_UCAST :
                             BRIDGING_MODE_TUNNEL_MCAST;
        } else if ((dst_mac && dst_mac_mask) || !dst_mac) {
            mode = BRIDGING_MODE_TUNNEL_DFLT;
        }
    }

    if (mode == BRIDGING_MODE_UNKNOWN)
        return -EINVAL;

    if (info[ROCKER_TLV_FLOW_GOTO_TBL]) {
        action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);
        if (action->goto_tbl != FLOW_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_GROUP_ID]);
        switch (mode) {
        case BRIDGING_MODE_VLAN_UCAST:
            if (action->write.group_id != GROUP_TYPE_L2_INTERFACE)
                return -EINVAL;
            break;
        case BRIDGING_MODE_VLAN_MCAST:
            if (action->write.group_id != GROUP_TYPE_L2_MCAST)
                return -EINVAL;
            break;
        case BRIDGING_MODE_VLAN_DFLT:
            if (action->write.group_id != GROUP_TYPE_L2_FLOOD)
                return -EINVAL;
            break;
        case BRIDGING_MODE_TUNNEL_MCAST:
            if (action->write.group_id != GROUP_TYPE_L2_OVERLAY)
                return -EINVAL;
            break;
        case BRIDGING_MODE_TUNNEL_DFLT:
            // XXX need L2 overlay flood type
            if (action->write.group_id != GROUP_TYPE_L2_OVERLAY)
                return -EINVAL;
            break;
        default:
            return -EINVAL;
        }
    }

    if (info[ROCKER_TLV_FLOW_TUN_LOG_LPORT]) {
        action->write.tun_log_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_TUN_LOG_LPORT]);
        if (mode != BRIDGING_MODE_TUNNEL_UCAST)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_OUT_LPORT])
        action->apply.out_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_OUT_LPORT]);

    return 0;
}

static int flow_cmd_add_unicast_routing(struct flow *flow,
                                        struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    enum {
        UNICAST_ROUTING_MODE_UNKNOWN,
        UNICAST_ROUTING_MODE_IPV4,
        UNICAST_ROUTING_MODE_IPV6,
    } mode = UNICAST_ROUTING_MODE_UNKNOWN;

    if (!info[ROCKER_TLV_FLOW_ETHERTYPE])
        return -EINVAL;

    key->tbl_id = FLOW_TABLE_UNICAST_ROUTING;

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_ETHERTYPE]);
    switch (key->eth.type) {
    case 0x0800:
        mode = UNICAST_ROUTING_MODE_IPV4;
        break;
    case 0x86dd:
        mode = UNICAST_ROUTING_MODE_IPV6;
        break;
    default:
        return -EINVAL;
    }

    switch (mode) {
    case UNICAST_ROUTING_MODE_IPV4:
        if (!info[ROCKER_TLV_FLOW_DST_IP])
            return -EINVAL;
        key->ipv4.addr.dst = rocker_tlv_get_u32(info[ROCKER_TLV_FLOW_DST_IP]);
        if (ipv4_addr_is_multicast(key->ipv4.addr.dst))
            return -EINVAL;
        if (info[ROCKER_TLV_FLOW_DST_IP_MASK])
            mask->ipv4.addr.dst =
                rocker_tlv_get_u32(info[ROCKER_TLV_FLOW_DST_IP_MASK]);
        break;
    case UNICAST_ROUTING_MODE_IPV6:
        if (!info[ROCKER_TLV_FLOW_DST_IPV6])
            return -EINVAL;
        memcpy(&key->ipv6.addr.dst,
               rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_IPV6]),
               sizeof(key->ipv6.addr.dst));
        if (ipv6_addr_is_multicast(&key->ipv6.addr.dst))
            return -EINVAL;
        if (info[ROCKER_TLV_FLOW_DST_IPV6_MASK])
            memcpy(&mask->ipv6.addr.dst,
                   rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_IPV6_MASK]),
                   sizeof(mask->ipv6.addr.dst));
        break;
    default:
        return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_GOTO_TBL]) {
        action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);
        if (action->goto_tbl != FLOW_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_GROUP_ID]);
        if (action->write.group_id != GROUP_TYPE_L3_UCAST)
            return -EINVAL;
    }

    return 0;
}

static int flow_cmd_add_multicast_routing(struct flow *flow,
                                          struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    enum {
        MULTICAST_ROUTING_MODE_UNKNOWN,
        MULTICAST_ROUTING_MODE_IPV4,
        MULTICAST_ROUTING_MODE_IPV6,
    } mode = MULTICAST_ROUTING_MODE_UNKNOWN;

    if (!info[ROCKER_TLV_FLOW_ETHERTYPE] ||
        !info[ROCKER_TLV_FLOW_VLAN_ID])
        return -EINVAL;

    key->tbl_id = FLOW_TABLE_MULTICAST_ROUTING;

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_ETHERTYPE]);
    switch (key->eth.type) {
    case 0x0800:
        mode = MULTICAST_ROUTING_MODE_IPV4;
        break;
    case 0x86dd:
        mode = MULTICAST_ROUTING_MODE_IPV6;
        break;
    default:
        return -EINVAL;
    }

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_FLOW_VLAN_ID]);

    switch (mode) {
    case MULTICAST_ROUTING_MODE_IPV4:

        if (info[ROCKER_TLV_FLOW_SRC_IP])
            key->ipv4.addr.src =
                rocker_tlv_get_u32(info[ROCKER_TLV_FLOW_SRC_IP]);

        if (info[ROCKER_TLV_FLOW_SRC_IP_MASK])
            mask->ipv4.addr.src =
                rocker_tlv_get_u32(info[ROCKER_TLV_FLOW_SRC_IP_MASK]);

        if (!info[ROCKER_TLV_FLOW_SRC_IP])
            if (mask->ipv4.addr.src != 0xffffffff)
                return -EINVAL;

        if (!info[ROCKER_TLV_FLOW_DST_IP])
            return -EINVAL;
        key->ipv4.addr.dst = rocker_tlv_get_u32(info[ROCKER_TLV_FLOW_DST_IP]);
        if (!ipv4_addr_is_multicast(key->ipv4.addr.dst))
            return -EINVAL;

        break;

    case MULTICAST_ROUTING_MODE_IPV6:

        if (info[ROCKER_TLV_FLOW_SRC_IPV6])
            memcpy(&key->ipv6.addr.src,
                   rocker_tlv_data(info[ROCKER_TLV_FLOW_SRC_IPV6]),
                   sizeof(key->ipv6.addr.src));

        if (info[ROCKER_TLV_FLOW_SRC_IPV6_MASK])
            memcpy(&mask->ipv6.addr.src,
                   rocker_tlv_data(info[ROCKER_TLV_FLOW_SRC_IPV6_MASK]),
                   sizeof(mask->ipv6.addr.src));

        if (!info[ROCKER_TLV_FLOW_SRC_IPV6])
            if (mask->ipv6.addr.src.addr32[0] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[1] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[2] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[3] != 0xffffffff)
                return -EINVAL;

        if (!info[ROCKER_TLV_FLOW_DST_IPV6])
            return -EINVAL;
        memcpy(&key->ipv6.addr.dst,
               rocker_tlv_data(info[ROCKER_TLV_FLOW_DST_IPV6]),
               sizeof(key->ipv6.addr.dst));
        if (!ipv6_addr_is_multicast(&key->ipv6.addr.dst))
            return -EINVAL;

        break;

    default:
        return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_GOTO_TBL]) {
        action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_FLOW_GOTO_TBL]);
        if (action->goto_tbl != FLOW_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_FLOW_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_FLOW_GROUP_ID]);
        if (action->write.group_id != GROUP_TYPE_L3_MCAST)
            return -EINVAL;
        action->write.vlan_id = key->eth.vlan_id;
    }

    return 0;
}

static int flow_cmd_add_acl(struct flow *flow, struct rocker_tlv **info)
{
    // XXX implement this
    return -ENOTSUP;
}

static int flow_cmd_add(struct flow_world *fw, uint64_t cookie,
                        struct rocker_tlv **tlvs)
{
    struct flow *flow = flow_find(fw, cookie);
    struct rocker_tlv *info[ROCKER_TLV_FLOW_INFO_MAX + 1];
    struct rocker_tlv *nest = NULL;
    enum flow_tbl_id tbl;
    uint32_t priority;
    uint32_t hardtime;
    uint32_t idletime = 0;
    int err = 0;

    if (flow)
        return -EEXIST;

    if (!tlvs[ROCKER_TLV_FLOW_TBL] ||
        !tlvs[ROCKER_TLV_FLOW_PRIORITY] ||
        !tlvs[ROCKER_TLV_FLOW_HARDTIME])
        return -EINVAL;

    tbl = rocker_tlv_get_le16(tlvs[ROCKER_TLV_FLOW_TBL]);
    priority = rocker_tlv_get_le32(tlvs[ROCKER_TLV_FLOW_PRIORITY]);
    hardtime = rocker_tlv_get_le32(tlvs[ROCKER_TLV_FLOW_HARDTIME]);

    if (tlvs[ROCKER_TLV_FLOW_IDLETIME]) {
        if (tlvs[ROCKER_TLV_FLOW_IG_PORT] ||
            tlvs[ROCKER_TLV_FLOW_VLAN] ||
            tlvs[ROCKER_TLV_FLOW_TERM_MAC])
            return -EINVAL;
        idletime = rocker_tlv_get_le32(tlvs[ROCKER_TLV_FLOW_IDLETIME]);
    }

    if (tlvs[ROCKER_TLV_FLOW_IG_PORT] && tbl == FLOW_TABLE_INGRESS_PORT)
        nest = tlvs[ROCKER_TLV_FLOW_IG_PORT];
    else if (tlvs[ROCKER_TLV_FLOW_VLAN] && tbl == FLOW_TABLE_VLAN)
        nest = tlvs[ROCKER_TLV_FLOW_VLAN];
    else if (tlvs[ROCKER_TLV_FLOW_TERM_MAC] &&
             tbl == FLOW_TABLE_TERMINATION_MAC)
        nest = tlvs[ROCKER_TLV_FLOW_TERM_MAC];
    else if (tlvs[ROCKER_TLV_FLOW_BRIDGING] && tbl == FLOW_TABLE_BRIDGING)
        nest = tlvs[ROCKER_TLV_FLOW_BRIDGING];
    else if (tlvs[ROCKER_TLV_FLOW_UNICAST_ROUTING] &&
             tbl == FLOW_TABLE_UNICAST_ROUTING)
        nest = tlvs[ROCKER_TLV_FLOW_UNICAST_ROUTING];
    else if (tlvs[ROCKER_TLV_FLOW_MULTICAST_ROUTING] &&
             tbl == FLOW_TABLE_MULTICAST_ROUTING)
        nest = tlvs[ROCKER_TLV_FLOW_MULTICAST_ROUTING];
    else if (tlvs[ROCKER_TLV_FLOW_ACL] && tbl == FLOW_TABLE_ACL_POLICY)
        nest = tlvs[ROCKER_TLV_FLOW_ACL];

    if (!nest)
        return -EINVAL;

    rocker_tlv_parse_nested(info, ROCKER_TLV_FLOW_INFO_MAX, nest);

    flow = flow_alloc(fw, cookie, priority, hardtime, idletime);
    if (!flow)
        return -EINVAL;

    switch (tbl) {
    case FLOW_TABLE_INGRESS_PORT:
        err = flow_cmd_add_ig_port(flow, info);
        break;
    case FLOW_TABLE_VLAN:
        err = flow_cmd_add_vlan(flow, info);
        break;
    case FLOW_TABLE_TERMINATION_MAC:
        err = flow_cmd_add_term_mac(flow, info);
        break;
    case FLOW_TABLE_BRIDGING:
        err = flow_cmd_add_bridging(flow, info);
        break;
    case FLOW_TABLE_UNICAST_ROUTING:
        err = flow_cmd_add_unicast_routing(flow, info);
        break;
    case FLOW_TABLE_MULTICAST_ROUTING:
        err = flow_cmd_add_multicast_routing(flow, info);
        break;
    case FLOW_TABLE_ACL_POLICY:
        err = flow_cmd_add_acl(flow, info);
        break;
    }

    if (err)
        goto err_cmd_add;

    err = flow_add(flow);
    if (err)
        goto err_cmd_add;

    return 0;

err_cmd_add:
        g_free(flow);
        return err;
}

static int flow_cmd_mod(struct flow_world *fw, uint64_t cookie,
                        struct rocker_tlv **tlvs)
{
    struct flow *flow = flow_find(fw, cookie);

    if (!flow)
        return -ENOENT;

    return flow_mod(flow);
}

static int flow_cmd_del(struct flow_world *fw, uint64_t cookie)
{
    struct flow *flow = flow_find(fw, cookie);

    if (!flow)
        return -ENOENT;

    flow_del(flow);
    g_free(flow);

    return 0;
}

static int flow_cmd_get_stats(struct flow_world *fw, uint64_t cookie,
                              struct desc_info *info, char *buf)
{
    struct flow *flow = flow_find(fw, cookie);
    size_t tlv_size;
    int pos;

    if (!flow)
        return -ENOENT;

    tlv_size = rocker_tlv_total_size(sizeof(uint32_t)) +  /* duration */
               rocker_tlv_total_size(sizeof(uint64_t)) +  /* rx_pkts */
               rocker_tlv_total_size(sizeof(uint64_t));   /* tx_ptks */

    if (tlv_size > desc_buf_size(info))
        return -EMSGSIZE;

    pos = 0;
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_FLOW_STAT_DURATION,
                        flow->stats.duration);
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_FLOW_STAT_RX_PKTS,
                        flow->stats.rx_pkts);
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_FLOW_STAT_TX_PKTS,
                        flow->stats.tx_pkts);

    return desc_set_buf(info, tlv_size);
}

static int flow_cmd(struct world *world, struct desc_info *info,
                    char *buf, uint16_t cmd,
                    struct rocker_tlv *cmd_info_tlv)
{
    struct flow_world *fw = world_private(world);
    struct rocker_tlv *tlvs[ROCKER_TLV_FLOW_MAX + 1];
    uint64_t cookie;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_FLOW_MAX, cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_FLOW_COOKIE])
        return -EINVAL;

    cookie = rocker_tlv_get_le64(tlvs[ROCKER_TLV_FLOW_COOKIE]);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_FLOW_ADD:
        return flow_cmd_add(fw, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_FLOW_MOD:
        return flow_cmd_mod(fw, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_FLOW_DEL:
        return flow_cmd_del(fw, cookie);
    case ROCKER_TLV_CMD_TYPE_FLOW_GET_STATS:
        return flow_cmd_get_stats(fw, cookie, info, buf);
    }

    return -EINVAL;
}

static void flow_default_bridging(struct flow_world *fw)
{
    struct flow *flow;
    struct group *group;

    group = group_alloc(fw);
    group->id = 1;
    group->type = GROUP_TYPE_L2_INTERFACE;
    group->action.out_lport = 0x00000002;
    group->action.pop_vlan_tag = true;
    group_add(group);

    /* pkts on VLAN 100 goto bridging mode VLAN dflt: group id 1 */
    flow = flow_alloc(fw, -4, 0, 0, 0);
    flow->key.tbl_id = FLOW_TABLE_BRIDGING;
    flow->key.eth.vlan_id = htons(100);
    memset(flow->mask.eth.dst.a, 0xff, sizeof(flow->mask.eth.dst.a));
    flow->action.write.group_id = 1;
    flow_add(flow);
}

static void flow_default_vlan(struct flow_world *fw)
{
    struct flow *flow;

    /* untagged pkt on port 0 to VLAN 100 */
    flow = flow_alloc(fw, -3, 0, 0, 0);
    flow->key.tbl_id = FLOW_TABLE_VLAN;
    flow->key.in_lport = 0x00000001;
    flow->mask.eth.vlan_id = htons(VLAN_VID_MASK);
    flow->action.goto_tbl = FLOW_TABLE_TERMINATION_MAC;
    flow->action.apply.new_vlan_id = htons(100);
    flow_add(flow);
}

static void flow_default_ig_port(struct flow_world *fw)
{
    struct flow *flow;

    /* default pkts from physical ports goto VLAN tbl */
    flow = flow_alloc(fw, -1, 0, 0, 0);
    flow->key.tbl_id = FLOW_TABLE_INGRESS_PORT;
    flow->key.in_lport = 0x00000000;
    flow->mask.in_lport = ROCKER_FP_PORTS_MAX + 1;
    flow->action.goto_tbl = FLOW_TABLE_VLAN;
    flow_add(flow);

    /* default pkts from overlay tunnels goto bridging tbl */
    flow = flow_alloc(fw, -2, 0, 0, 0);
    flow->key.tbl_id = FLOW_TABLE_INGRESS_PORT;
    flow->key.in_lport = ROCKER_TUNNEL_LPORT;
    flow->mask.in_lport = 0xffff0000;
    flow->action.goto_tbl = FLOW_TABLE_BRIDGING;
    flow_add(flow);
}

static int flow_world_init(struct world *world)
{
    struct flow_world *fw = world_private(world);

    fw->world = world;

    fw->flow_tbl = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         NULL, g_free);
    if (!fw->flow_tbl)
        return -ENOMEM;

    fw->group_tbl = g_hash_table_new_full(g_int_hash, g_int_equal,
                                          NULL, g_free);
    if (!fw->group_tbl)
        goto err_group_tbl;

    // XXX hardcode some artificial table max values
    fw->flow_tbl_max_size = 100;
    fw->group_tbl_max_size = 100;

    flow_default_ig_port(fw);
    flow_default_vlan(fw);
    flow_default_bridging(fw);

    return 0;

err_group_tbl:
    g_hash_table_destroy(fw->flow_tbl);
    return -ENOMEM;
}

static void flow_world_uninit(struct world *world)
{
    struct flow_world *fw = world_private(world);

    g_hash_table_destroy(fw->group_tbl);
    g_hash_table_destroy(fw->flow_tbl);
}

static struct world_ops flow_ops = {
    .init = flow_world_init,
    .uninit = flow_world_uninit,
    .ig = flow_ig,
    .cmd = flow_cmd,
};

struct world *flow_world_alloc(struct rocker *r)
{
    return world_alloc(r, sizeof(struct flow_world),
                       ROCKER_WORLD_TYPE_FLOW, &flow_ops);
}
