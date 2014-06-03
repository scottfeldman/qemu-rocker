/*
 * QEMU rocker switch emulation - OF-DPA flow processing support
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

#include "net/eth.h"
#include "qemu/iov.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_desc.h"
#include "rocker_flow.h"
#include "rocker_of_dpa.h"

enum of_dpa_tbl_id {
    OF_DPA_TABLE_INGRESS_PORT = 0,
    OF_DPA_TABLE_VLAN = 10,
    OF_DPA_TABLE_TERMINATION_MAC = 20,
    OF_DPA_TABLE_UNICAST_ROUTING = 30,
    OF_DPA_TABLE_MULTICAST_ROUTING = 40,
    OF_DPA_TABLE_BRIDGING = 50,
    OF_DPA_TABLE_ACL_POLICY = 60,
};

struct of_dpa_world {
    struct world *world;
    struct flow_sys *fs;
    unsigned int flow_tbl_max_size;
    unsigned int group_tbl_max_size;
};

static void of_dpa_ig_port_build_match(struct flow_context *fc,
                                       struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_INGRESS_PORT;
    match->value.in_lport = fc->in_lport;
    match->width = FLOW_KEY_WIDTH(tbl_id);
}

static void of_dpa_vlan_build_match(struct flow_context *fc,
                                    struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_VLAN;
    match->value.in_lport = fc->in_lport;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    match->width = FLOW_KEY_WIDTH(eth.vlan_id);
}

static void of_dpa_vlan_insert(struct flow_context *fc, struct flow *flow)
{
    if (flow->action.apply.new_vlan_id) {
        flow_pkt_insert_vlan(fc);
        fc->fields.vlanhdr->h_proto = htons(ETH_P_VLAN);
        fc->fields.vlanhdr->h_tci = flow->action.apply.new_vlan_id;
    }
}

static void of_dpa_term_mac_build_match(struct flow_context *fc,
                                        struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_TERMINATION_MAC;
    match->value.in_lport = fc->in_lport;
    match->value.eth.type = *fc->fields.h_proto;
    match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->width = FLOW_KEY_WIDTH(eth.type);
}

static void of_dpa_term_mac_miss(struct flow_sys *fs, struct flow_context *fc)
{
    flow_ig_tbl(fs, fc, OF_DPA_TABLE_BRIDGING);
}

static void of_dpa_copy_to_controller(struct flow_context *fc,
                                      struct flow *flow)
{
    if (flow->action.apply.out_lport) {
        // XXX send copy of pkt to controller, out_lport must
        // XXX be controller lport
    }
}

static void of_dpa_bridging_build_match(struct flow_context *fc,
                                        struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_BRIDGING;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    else if (fc->tunnel_id)
        match->value.tunnel_id = fc->tunnel_id;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->width = FLOW_KEY_WIDTH(eth.dst);
}

static void of_dpa_bridging_miss(struct flow_sys *fs, struct flow_context *fc)
{
    flow_ig_tbl(fs, fc, OF_DPA_TABLE_ACL_POLICY);
}

static void of_dpa_bridging_action_write(struct flow_context *fc,
                                         struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.tun_log_lport = flow->action.write.tun_log_lport;
}

static void of_dpa_unicast_routing_build_match(struct flow_context *fc,
                                               struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_UNICAST_ROUTING;
    match->value.eth.type = *fc->fields.h_proto;
    if (fc->fields.ipv4hdr)
        match->value.ipv4.addr.dst = fc->fields.ipv4hdr->ip_dst;
    if (fc->fields.ipv6_dst_addr)
        memcpy(&match->value.ipv6.addr.dst, fc->fields.ipv6_dst_addr,
               sizeof(match->value.ipv6.addr.dst));
    match->width = FLOW_KEY_WIDTH(ipv6.addr.dst);
}

static void of_dpa_unicast_routing_action_write(struct flow_context *fc,
                                                struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
}

static void of_dpa_multicast_routing_build_match(struct flow_context *fc,
                                                 struct flow_match *match)
{
    match->value.tbl_id = OF_DPA_TABLE_MULTICAST_ROUTING;
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

static void of_dpa_multicast_routing_action_write(struct flow_context *fc,
                                                  struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.vlan_id = flow->action.write.vlan_id;
}

static void of_dpa_eg(struct world *world, uint32_t lport, struct iovec *iov,
                      int iovcnt)
{
    rocker_port_eg(world_rocker(world), lport, iov, iovcnt);
}

static struct flow_tbl_ops of_dpa_tbl_ops[] = {
    [OF_DPA_TABLE_INGRESS_PORT] = {
        .build_match = of_dpa_ig_port_build_match,
    },
    [OF_DPA_TABLE_VLAN] = {
        .build_match = of_dpa_vlan_build_match,
        .action_apply = of_dpa_vlan_insert,
    },
    [OF_DPA_TABLE_TERMINATION_MAC] = {
        .build_match = of_dpa_term_mac_build_match,
        .miss = of_dpa_term_mac_miss,
        .action_apply = of_dpa_copy_to_controller,
    },
    [OF_DPA_TABLE_BRIDGING] = {
        .build_match = of_dpa_bridging_build_match,
        .miss = of_dpa_bridging_miss,
        .action_apply = of_dpa_copy_to_controller,
        .action_write = of_dpa_bridging_action_write,
        .eg = of_dpa_eg,
    },
    [OF_DPA_TABLE_UNICAST_ROUTING] = {
        .build_match = of_dpa_unicast_routing_build_match,
        .action_write = of_dpa_unicast_routing_action_write,
        .eg = of_dpa_eg,
    },
    [OF_DPA_TABLE_MULTICAST_ROUTING] = {
        .build_match = of_dpa_multicast_routing_build_match,
        .action_write = of_dpa_multicast_routing_action_write,
        .eg = of_dpa_eg,
    },
    [OF_DPA_TABLE_ACL_POLICY] = {
        // XXX implement this
    },
};

static ssize_t of_dpa_ig(struct world *world, uint32_t lport,
                         const struct iovec *iov, int iovcnt)
{
    struct of_dpa_world *ow = world_private(world);
    struct iovec iov_copy[iovcnt + 2];
    struct flow_context fc = {
        .in_lport = lport,
        .iov = iov_copy,
        .iovcnt = iovcnt + 2,
    };

    flow_pkt_parse(&fc, iov, iovcnt);
    flow_ig_tbl(ow->fs, &fc, OF_DPA_TABLE_INGRESS_PORT);

    return iov_size(iov, iovcnt);
}

#define ROCKER_TUNNEL_LPORT 0x00010000

static int of_dpa_cmd_add_ig_port(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_action *action = &flow->action;
    bool overlay_tunnel;

    if (!info[ROCKER_TLV_OF_DPA_IN_LPORT] ||
        !info[ROCKER_TLV_OF_DPA_GOTO_TBL])
        return -EINVAL;

    key->tbl_id = OF_DPA_TABLE_INGRESS_PORT;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_IN_LPORT]);
    overlay_tunnel = !!(key->in_lport & ROCKER_TUNNEL_LPORT);

    action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);

    if (!overlay_tunnel && action->goto_tbl != OF_DPA_TABLE_VLAN)
        return -EINVAL;

    if (overlay_tunnel && action->goto_tbl != OF_DPA_TABLE_BRIDGING)
        return -EINVAL;

    return 0;
}

static int of_dpa_cmd_add_vlan(struct flow *flow, struct rocker_tlv **info)
{
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_action *action = &flow->action;
    bool untagged;

    if (!info[ROCKER_TLV_OF_DPA_IN_LPORT] ||
        !info[ROCKER_TLV_OF_DPA_VLAN_ID] ||
        !info[ROCKER_TLV_OF_DPA_VLAN_ID_MASK] ||
        !info[ROCKER_TLV_OF_DPA_GOTO_TBL])
        return -EINVAL;

    key->tbl_id = OF_DPA_TABLE_VLAN;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_IN_LPORT]);
    if (1 < key->in_lport || key->in_lport > 63)
        return -EINVAL;
    mask->in_lport = 0x0000003f;

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID]);
    mask->eth.vlan_id =
        rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID_MASK]);
    if (mask->eth.vlan_id == htons(0x1fff))
        untagged = false; /* filtering */
    else if (mask->eth.vlan_id == htons(0x0fff))
        untagged = true;
    else
        return -EINVAL;

    action->goto_tbl = rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);

    if (action->goto_tbl != OF_DPA_TABLE_TERMINATION_MAC)
        return -EINVAL;

    if (untagged) {
        if (!info[ROCKER_TLV_OF_DPA_NEW_VLAN_ID])
            return -EINVAL;
        action->apply.new_vlan_id =
            rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_NEW_VLAN_ID]);
        if (1 < ntohs(action->apply.new_vlan_id) ||
            ntohs(action->apply.new_vlan_id) > 4094)
            return -EINVAL;
    }

    return 0;
}

static int of_dpa_cmd_add_term_mac(struct flow *flow, struct rocker_tlv **info)
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

    if (!info[ROCKER_TLV_OF_DPA_IN_LPORT] ||
        !info[ROCKER_TLV_OF_DPA_IN_LPORT_MASK] ||
        !info[ROCKER_TLV_OF_DPA_ETHERTYPE] ||
        !info[ROCKER_TLV_OF_DPA_DST_MAC] ||
        !info[ROCKER_TLV_OF_DPA_DST_MAC_MASK] ||
        !info[ROCKER_TLV_OF_DPA_VLAN_ID] ||
        !info[ROCKER_TLV_OF_DPA_VLAN_ID_MASK])
        return -EINVAL;

    key->tbl_id = OF_DPA_TABLE_TERMINATION_MAC;

    key->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_IN_LPORT]);
    if (1 < key->in_lport || key->in_lport > 63)
        return -EINVAL;
    mask->in_lport = rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_IN_LPORT_MASK]);

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_ETHERTYPE]);
    if (key->eth.type != 0x0800 || key->eth.type != 0x86dd)
        return -EINVAL;

    memcpy(key->eth.dst.a, rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_MAC]),
           sizeof(key->eth.dst.a));
    memcpy(mask->eth.dst.a,
           rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_MAC_MASK]),
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

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID]);
    mask->eth.vlan_id =
        rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID_MASK]);

    if (info[ROCKER_TLV_OF_DPA_GOTO_TBL]) {
        action->goto_tbl =
            rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);
    
        if (action->goto_tbl != OF_DPA_TABLE_UNICAST_ROUTING ||
            action->goto_tbl != OF_DPA_TABLE_MULTICAST_ROUTING)
            return -EINVAL;

        if (unicast && action->goto_tbl != OF_DPA_TABLE_UNICAST_ROUTING)
            return -EINVAL;

        if (multicast && action->goto_tbl != OF_DPA_TABLE_MULTICAST_ROUTING)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_OUT_LPORT])
        action->apply.out_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_OUT_LPORT]);

    return 0;
}

static int of_dpa_cmd_add_bridging(struct flow *flow, struct rocker_tlv **info)
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

    key->tbl_id = OF_DPA_TABLE_BRIDGING;

    if (info[ROCKER_TLV_OF_DPA_VLAN_ID])
        key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID]);

    if (info[ROCKER_TLV_OF_DPA_TUNNEL_ID])
        key->tunnel_id = rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_TUNNEL_ID]);

    /* can't do VLAN bridging and tunnel bridging at same time */
    if (key->eth.vlan_id && key->tunnel_id)
        return -EINVAL;

    if (info[ROCKER_TLV_OF_DPA_DST_MAC]) {
        memcpy(key->eth.dst.a, rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_MAC]),
               sizeof(key->eth.dst.a));
        dst_mac = true;
        unicast = (key->eth.dst.a[5] & 0x01) == 0x00;
    }

    if (info[ROCKER_TLV_OF_DPA_DST_MAC_MASK]) {
        memcpy(mask->eth.dst.a,
               rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_MAC_MASK]),
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

    if (info[ROCKER_TLV_OF_DPA_GOTO_TBL]) {
        action->goto_tbl =
            rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);
        if (action->goto_tbl != OF_DPA_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_GROUP_ID]);
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

    if (info[ROCKER_TLV_OF_DPA_TUN_LOG_LPORT]) {
        action->write.tun_log_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_TUN_LOG_LPORT]);
        if (mode != BRIDGING_MODE_TUNNEL_UCAST)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_OUT_LPORT])
        action->apply.out_lport =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_OUT_LPORT]);

    return 0;
}

static int of_dpa_cmd_add_unicast_routing(struct flow *flow,
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

    if (!info[ROCKER_TLV_OF_DPA_ETHERTYPE])
        return -EINVAL;

    key->tbl_id = OF_DPA_TABLE_UNICAST_ROUTING;

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_ETHERTYPE]);
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
        if (!info[ROCKER_TLV_OF_DPA_DST_IP])
            return -EINVAL;
        key->ipv4.addr.dst = rocker_tlv_get_u32(info[ROCKER_TLV_OF_DPA_DST_IP]);
        if (ipv4_addr_is_multicast(key->ipv4.addr.dst))
            return -EINVAL;
        if (info[ROCKER_TLV_OF_DPA_DST_IP_MASK])
            mask->ipv4.addr.dst =
                rocker_tlv_get_u32(info[ROCKER_TLV_OF_DPA_DST_IP_MASK]);
        break;
    case UNICAST_ROUTING_MODE_IPV6:
        if (!info[ROCKER_TLV_OF_DPA_DST_IPV6])
            return -EINVAL;
        memcpy(&key->ipv6.addr.dst,
               rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_IPV6]),
               sizeof(key->ipv6.addr.dst));
        if (ipv6_addr_is_multicast(&key->ipv6.addr.dst))
            return -EINVAL;
        if (info[ROCKER_TLV_OF_DPA_DST_IPV6_MASK])
            memcpy(&mask->ipv6.addr.dst,
                   rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_IPV6_MASK]),
                   sizeof(mask->ipv6.addr.dst));
        break;
    default:
        return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_GOTO_TBL]) {
        action->goto_tbl =
            rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);
        if (action->goto_tbl != OF_DPA_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_GROUP_ID]);
        if (action->write.group_id != GROUP_TYPE_L3_UCAST)
            return -EINVAL;
    }

    return 0;
}

static int of_dpa_cmd_add_multicast_routing(struct flow *flow,
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

    if (!info[ROCKER_TLV_OF_DPA_ETHERTYPE] ||
        !info[ROCKER_TLV_OF_DPA_VLAN_ID])
        return -EINVAL;

    key->tbl_id = OF_DPA_TABLE_MULTICAST_ROUTING;

    key->eth.type = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_ETHERTYPE]);
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

    key->eth.vlan_id = rocker_tlv_get_u16(info[ROCKER_TLV_OF_DPA_VLAN_ID]);

    switch (mode) {
    case MULTICAST_ROUTING_MODE_IPV4:

        if (info[ROCKER_TLV_OF_DPA_SRC_IP])
            key->ipv4.addr.src =
                rocker_tlv_get_u32(info[ROCKER_TLV_OF_DPA_SRC_IP]);

        if (info[ROCKER_TLV_OF_DPA_SRC_IP_MASK])
            mask->ipv4.addr.src =
                rocker_tlv_get_u32(info[ROCKER_TLV_OF_DPA_SRC_IP_MASK]);

        if (!info[ROCKER_TLV_OF_DPA_SRC_IP])
            if (mask->ipv4.addr.src != 0xffffffff)
                return -EINVAL;

        if (!info[ROCKER_TLV_OF_DPA_DST_IP])
            return -EINVAL;
        key->ipv4.addr.dst = rocker_tlv_get_u32(info[ROCKER_TLV_OF_DPA_DST_IP]);
        if (!ipv4_addr_is_multicast(key->ipv4.addr.dst))
            return -EINVAL;

        break;

    case MULTICAST_ROUTING_MODE_IPV6:

        if (info[ROCKER_TLV_OF_DPA_SRC_IPV6])
            memcpy(&key->ipv6.addr.src,
                   rocker_tlv_data(info[ROCKER_TLV_OF_DPA_SRC_IPV6]),
                   sizeof(key->ipv6.addr.src));

        if (info[ROCKER_TLV_OF_DPA_SRC_IPV6_MASK])
            memcpy(&mask->ipv6.addr.src,
                   rocker_tlv_data(info[ROCKER_TLV_OF_DPA_SRC_IPV6_MASK]),
                   sizeof(mask->ipv6.addr.src));

        if (!info[ROCKER_TLV_OF_DPA_SRC_IPV6])
            if (mask->ipv6.addr.src.addr32[0] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[1] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[2] != 0xffffffff &&
                mask->ipv6.addr.src.addr32[3] != 0xffffffff)
                return -EINVAL;

        if (!info[ROCKER_TLV_OF_DPA_DST_IPV6])
            return -EINVAL;
        memcpy(&key->ipv6.addr.dst,
               rocker_tlv_data(info[ROCKER_TLV_OF_DPA_DST_IPV6]),
               sizeof(key->ipv6.addr.dst));
        if (!ipv6_addr_is_multicast(&key->ipv6.addr.dst))
            return -EINVAL;

        break;

    default:
        return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_GOTO_TBL]) {
        action->goto_tbl =
            rocker_tlv_get_le16(info[ROCKER_TLV_OF_DPA_GOTO_TBL]);
        if (action->goto_tbl != OF_DPA_TABLE_ACL_POLICY)
            return -EINVAL;
    }

    if (info[ROCKER_TLV_OF_DPA_GROUP_ID]) {
        action->write.group_id =
            rocker_tlv_get_le32(info[ROCKER_TLV_OF_DPA_GROUP_ID]);
        if (action->write.group_id != GROUP_TYPE_L3_MCAST)
            return -EINVAL;
        action->write.vlan_id = key->eth.vlan_id;
    }

    return 0;
}

static int of_dpa_cmd_add_acl(struct flow *flow, struct rocker_tlv **info)
{
    // XXX implement this
    return -ENOTSUP;
}

static int of_dpa_cmd_add(struct of_dpa_world *ow, uint64_t cookie,
                          struct rocker_tlv **tlvs)
{
    struct flow_sys *fs = ow->fs;
    struct flow *flow = flow_find(fs, cookie);
    struct rocker_tlv *info[ROCKER_TLV_OF_DPA_INFO_MAX + 1];
    struct rocker_tlv *nest = NULL;
    enum of_dpa_tbl_id tbl;
    uint32_t priority;
    uint32_t hardtime;
    uint32_t idletime = 0;
    int err = 0;

    if (flow)
        return -EEXIST;

    if (!tlvs[ROCKER_TLV_OF_DPA_TBL] ||
        !tlvs[ROCKER_TLV_OF_DPA_PRIORITY] ||
        !tlvs[ROCKER_TLV_OF_DPA_HARDTIME])
        return -EINVAL;

    tbl = rocker_tlv_get_le16(tlvs[ROCKER_TLV_OF_DPA_TBL]);
    priority = rocker_tlv_get_le32(tlvs[ROCKER_TLV_OF_DPA_PRIORITY]);
    hardtime = rocker_tlv_get_le32(tlvs[ROCKER_TLV_OF_DPA_HARDTIME]);

    if (tlvs[ROCKER_TLV_OF_DPA_IDLETIME]) {
        if (tlvs[ROCKER_TLV_OF_DPA_IG_PORT] ||
            tlvs[ROCKER_TLV_OF_DPA_VLAN] ||
            tlvs[ROCKER_TLV_OF_DPA_TERM_MAC])
            return -EINVAL;
        idletime = rocker_tlv_get_le32(tlvs[ROCKER_TLV_OF_DPA_IDLETIME]);
    }

    if (tlvs[ROCKER_TLV_OF_DPA_IG_PORT] && tbl == OF_DPA_TABLE_INGRESS_PORT)
        nest = tlvs[ROCKER_TLV_OF_DPA_IG_PORT];
    else if (tlvs[ROCKER_TLV_OF_DPA_VLAN] && tbl == OF_DPA_TABLE_VLAN)
        nest = tlvs[ROCKER_TLV_OF_DPA_VLAN];
    else if (tlvs[ROCKER_TLV_OF_DPA_TERM_MAC] &&
             tbl == OF_DPA_TABLE_TERMINATION_MAC)
        nest = tlvs[ROCKER_TLV_OF_DPA_TERM_MAC];
    else if (tlvs[ROCKER_TLV_OF_DPA_BRIDGING] && tbl == OF_DPA_TABLE_BRIDGING)
        nest = tlvs[ROCKER_TLV_OF_DPA_BRIDGING];
    else if (tlvs[ROCKER_TLV_OF_DPA_UNICAST_ROUTING] &&
             tbl == OF_DPA_TABLE_UNICAST_ROUTING)
        nest = tlvs[ROCKER_TLV_OF_DPA_UNICAST_ROUTING];
    else if (tlvs[ROCKER_TLV_OF_DPA_MULTICAST_ROUTING] &&
             tbl == OF_DPA_TABLE_MULTICAST_ROUTING)
        nest = tlvs[ROCKER_TLV_OF_DPA_MULTICAST_ROUTING];
    else if (tlvs[ROCKER_TLV_OF_DPA_ACL] && tbl == OF_DPA_TABLE_ACL_POLICY)
        nest = tlvs[ROCKER_TLV_OF_DPA_ACL];

    if (!nest)
        return -EINVAL;

    rocker_tlv_parse_nested(info, ROCKER_TLV_OF_DPA_INFO_MAX, nest);

    flow = flow_alloc(fs, cookie, priority, hardtime, idletime);
    if (!flow)
        return -EINVAL;

    switch (tbl) {
    case OF_DPA_TABLE_INGRESS_PORT:
        err = of_dpa_cmd_add_ig_port(flow, info);
        break;
    case OF_DPA_TABLE_VLAN:
        err = of_dpa_cmd_add_vlan(flow, info);
        break;
    case OF_DPA_TABLE_TERMINATION_MAC:
        err = of_dpa_cmd_add_term_mac(flow, info);
        break;
    case OF_DPA_TABLE_BRIDGING:
        err = of_dpa_cmd_add_bridging(flow, info);
        break;
    case OF_DPA_TABLE_UNICAST_ROUTING:
        err = of_dpa_cmd_add_unicast_routing(flow, info);
        break;
    case OF_DPA_TABLE_MULTICAST_ROUTING:
        err = of_dpa_cmd_add_multicast_routing(flow, info);
        break;
    case OF_DPA_TABLE_ACL_POLICY:
        err = of_dpa_cmd_add_acl(flow, info);
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

static int of_dpa_cmd_mod(struct of_dpa_world *ow, uint64_t cookie,
                          struct rocker_tlv **tlvs)
{
    struct flow *flow = flow_find(ow->fs, cookie);

    if (!flow)
        return -ENOENT;

    return flow_mod(flow);
}

static int of_dpa_cmd_del(struct of_dpa_world *ow, uint64_t cookie)
{
    struct flow *flow = flow_find(ow->fs, cookie);

    if (!flow)
        return -ENOENT;

    flow_del(flow);

    return 0;
}

static int of_dpa_cmd_get_stats(struct of_dpa_world *ow, uint64_t cookie,
                                struct desc_info *info, char *buf)
{
    struct flow *flow = flow_find(ow->fs, cookie);
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
    rocker_tlv_put_le32(buf, &pos, ROCKER_TLV_OF_DPA_STAT_DURATION,
                        flow->stats.duration);
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_OF_DPA_STAT_RX_PKTS,
                        flow->stats.rx_pkts);
    rocker_tlv_put_le64(buf, &pos, ROCKER_TLV_OF_DPA_STAT_TX_PKTS,
                        flow->stats.tx_pkts);

    return desc_set_buf(info, tlv_size);
}

static int of_dpa_cmd(struct world *world, struct desc_info *info,
                     char *buf, uint16_t cmd,
                     struct rocker_tlv *cmd_info_tlv)
{
    struct of_dpa_world *ow = world_private(world);
    struct rocker_tlv *tlvs[ROCKER_TLV_OF_DPA_MAX + 1];
    uint64_t cookie;

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_OF_DPA_MAX, cmd_info_tlv);

    if (!tlvs[ROCKER_TLV_OF_DPA_COOKIE])
        return -EINVAL;

    cookie = rocker_tlv_get_le64(tlvs[ROCKER_TLV_OF_DPA_COOKIE]);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_OF_DPA_ADD:
        return of_dpa_cmd_add(ow, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_OF_DPA_MOD:
        return of_dpa_cmd_mod(ow, cookie, tlvs);
    case ROCKER_TLV_CMD_TYPE_OF_DPA_DEL:
        return of_dpa_cmd_del(ow, cookie);
    case ROCKER_TLV_CMD_TYPE_OF_DPA_GET_STATS:
        return of_dpa_cmd_get_stats(ow, cookie, info, buf);
    }

    return -EINVAL;
}

static void of_dpa_default_bridging(struct of_dpa_world *ow)
{
    struct flow *flow;
    struct group *group;

    group = group_alloc(ow->fs);
    group->id = 1;
//    group->type = GROUP_TYPE_L2_INTERFACE;
    group->action.out_lport = 0x00000002;
    group->action.pop_vlan_tag = true;
    group_add(group);

    /* pkts on VLAN 100 goto bridging mode VLAN dflt: group id 1 */
    flow = flow_alloc(ow->fs, flow_sys_another_cookie(ow->fs), 0, 0, 0);
    flow->key.tbl_id = OF_DPA_TABLE_BRIDGING;
    flow->key.eth.vlan_id = htons(100);
    memset(flow->mask.eth.dst.a, 0xff, sizeof(flow->mask.eth.dst.a));
    flow->action.write.group_id = 1;
    flow_add(flow);
}

static void of_dpa_default_vlan(struct of_dpa_world *ow)
{
    struct flow *flow;

    /* untagged pkt on port 0 to VLAN 100 */
    flow = flow_alloc(ow->fs, flow_sys_another_cookie(ow->fs), 0, 0, 0);
    flow->key.tbl_id = OF_DPA_TABLE_VLAN;
    flow->key.in_lport = 0x00000001;
    flow->mask.eth.vlan_id = htons(VLAN_VID_MASK);
    flow->action.goto_tbl = OF_DPA_TABLE_TERMINATION_MAC;
    flow->action.apply.new_vlan_id = htons(100);
    flow_add(flow);
}

static void of_dpa_default_ig_port(struct of_dpa_world *ow)
{
    struct flow *flow;

    /* default pkts from physical ports goto VLAN tbl */
    flow = flow_alloc(ow->fs, flow_sys_another_cookie(ow->fs), 0, 0, 0);
    flow->key.tbl_id = OF_DPA_TABLE_INGRESS_PORT;
    flow->key.in_lport = 0x00000000;
    flow->mask.in_lport = ROCKER_FP_PORTS_MAX + 1;
    flow->action.goto_tbl = OF_DPA_TABLE_VLAN;
    flow_add(flow);

    /* default pkts from overlay tunnels goto bridging tbl */
    flow = flow_alloc(ow->fs, flow_sys_another_cookie(ow->fs), 0, 0, 0);
    flow->key.tbl_id = OF_DPA_TABLE_INGRESS_PORT;
    flow->key.in_lport = ROCKER_TUNNEL_LPORT;
    flow->mask.in_lport = 0xffff0000;
    flow->action.goto_tbl = OF_DPA_TABLE_BRIDGING;
    flow_add(flow);
}

static int of_dpa_world_init(struct world *world)
{
    struct of_dpa_world *ow = world_private(world);

    ow->world = world;
    ow->fs = flow_sys_alloc(world, of_dpa_tbl_ops);
    if (!ow->fs)
        return -ENOMEM;

    // XXX hardcode some artificial table max values
    ow->flow_tbl_max_size = 100;
    ow->group_tbl_max_size = 100;

    of_dpa_default_ig_port(ow);
    of_dpa_default_vlan(ow);
    of_dpa_default_bridging(ow);

    return 0;
}

static void of_dpa_world_uninit(struct world *world)
{
    struct of_dpa_world *ow = world_private(world);

    flow_sys_free(ow->fs);
}

static struct world_ops of_dpa_ops = {
    .init = of_dpa_world_init,
    .uninit = of_dpa_world_uninit,
    .ig = of_dpa_ig,
    .cmd = of_dpa_cmd,
};

struct world *of_dpa_world_alloc(struct rocker *r)
{
    return world_alloc(r, sizeof(struct of_dpa_world),
                       ROCKER_WORLD_TYPE_OF_DPA, &of_dpa_ops);
}
