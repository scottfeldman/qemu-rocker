/*
 * QEMU rocker switch emulation - traditional L2/L3 processing support
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
#include "rocker_l2l3.h"

enum l2l3_tbl_id {
    L2L3_TABLE_INGRESS_PORT = 0,
    L2L3_TABLE_VLAN,
    L2L3_TABLE_TERMINATION_MAC,
    L2L3_TABLE_UNICAST_ROUTING,
    L2L3_TABLE_MULTICAST_ROUTING,
    L2L3_TABLE_BRIDGING,
    L2L3_TABLE_ACL_POLICY,
};

struct l2l3_world {
    struct world *world;
    struct flow_sys *fs;
};

static void l2l3_ig_port_build_match(struct flow_context *fc,
                                     struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_INGRESS_PORT;
    match->value.in_lport = fc->in_lport;
    match->value.width = FLOW_KEY_WIDTH(tbl_id);
}

static void l2l3_vlan_build_match(struct flow_context *fc,
                                  struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_VLAN;
    match->value.in_lport = fc->in_lport;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    match->value.width = FLOW_KEY_WIDTH(eth.vlan_id);
}

static void l2l3_vlan_insert(struct flow_context *fc, struct flow *flow)
{
    if (flow->action.apply.new_vlan_id) {
        flow_pkt_insert_vlan(fc);
        fc->fields.vlanhdr->h_proto = htons(ETH_P_VLAN);
        fc->fields.vlanhdr->h_tci = flow->action.apply.new_vlan_id;
    }
}

static void l2l3_term_mac_build_match(struct flow_context *fc,
                                      struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_TERMINATION_MAC;
    match->value.in_lport = fc->in_lport;
    match->value.eth.type = *fc->fields.h_proto;
    match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->value.width = FLOW_KEY_WIDTH(eth.type);
}

static void l2l3_term_mac_miss(struct flow_sys *fs, struct flow_context *fc)
{
    flow_ig_tbl(fs, fc, L2L3_TABLE_BRIDGING);
}

static void l2l3_copy_to_controller(struct flow_context *fc,
                                    struct flow *flow)
{
    if (flow->action.apply.out_lport) {
        // XXX send copy of pkt to controller, out_lport must
        // XXX be controller lport
    }
}

static void l2l3_bridging_build_match(struct flow_context *fc,
                                      struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_BRIDGING;
    if (fc->fields.vlanhdr)
        match->value.eth.vlan_id = fc->fields.vlanhdr->h_tci;
    else if (fc->tunnel_id)
        match->value.tunnel_id = fc->tunnel_id;
    memcpy(match->value.eth.dst.a, fc->fields.ethhdr->h_dest,
           sizeof(match->value.eth.dst.a));
    match->value.width = FLOW_KEY_WIDTH(eth.dst);
}

static void l2l3_bridging_miss(struct flow_sys *fs, struct flow_context *fc)
{
    flow_ig_tbl(fs, fc, L2L3_TABLE_ACL_POLICY);
}

static void l2l3_bridging_action_write(struct flow_context *fc,
                                       struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.tun_log_lport = flow->action.write.tun_log_lport;
}

static void l2l3_unicast_routing_build_match(struct flow_context *fc,
                                             struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_UNICAST_ROUTING;
    match->value.eth.type = *fc->fields.h_proto;
    if (fc->fields.ipv4hdr)
        match->value.ipv4.addr.dst = fc->fields.ipv4hdr->ip_dst;
    if (fc->fields.ipv6_dst_addr)
        memcpy(&match->value.ipv6.addr.dst, fc->fields.ipv6_dst_addr,
               sizeof(match->value.ipv6.addr.dst));
    match->value.width = FLOW_KEY_WIDTH(ipv6.addr.dst);
}

static void l2l3_unicast_routing_action_write(struct flow_context *fc,
                                              struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
}

static void l2l3_multicast_routing_build_match(struct flow_context *fc,
                                               struct flow_match *match)
{
    match->value.tbl_id = L2L3_TABLE_MULTICAST_ROUTING;
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
    match->value.width = FLOW_KEY_WIDTH(ipv6.addr.dst);
}

static void l2l3_multicast_routing_action_write(struct flow_context *fc,
                                                struct flow *flow)
{
    fc->action_set.write.group_id = flow->action.write.group_id;
    fc->action_set.write.vlan_id = flow->action.write.vlan_id;
}

static void l2l3_eg(struct world *world, struct flow_context *fc,
                    uint32_t out_lport)
{
    if (out_lport == 0)
        rx_produce(world, fc->in_lport, fc->iov, fc->iovcnt);
    else
        rocker_port_eg(world_rocker(world), out_lport,
                       fc->iov, fc->iovcnt);
}

static struct flow_tbl_ops l2l3_tbl_ops[] = {
    [L2L3_TABLE_INGRESS_PORT] = {
        .build_match = l2l3_ig_port_build_match,
    },
    [L2L3_TABLE_VLAN] = {
        .build_match = l2l3_vlan_build_match,
        .action_apply = l2l3_vlan_insert,
    },
    [L2L3_TABLE_TERMINATION_MAC] = {
        .build_match = l2l3_term_mac_build_match,
        .miss = l2l3_term_mac_miss,
        .action_apply = l2l3_copy_to_controller,
    },
    [L2L3_TABLE_BRIDGING] = {
        .build_match = l2l3_bridging_build_match,
        .miss = l2l3_bridging_miss,
        .action_apply = l2l3_copy_to_controller,
        .action_write = l2l3_bridging_action_write,
        .eg = l2l3_eg,
    },
    [L2L3_TABLE_UNICAST_ROUTING] = {
        .build_match = l2l3_unicast_routing_build_match,
        .action_write = l2l3_unicast_routing_action_write,
        .eg = l2l3_eg,
    },
    [L2L3_TABLE_MULTICAST_ROUTING] = {
        .build_match = l2l3_multicast_routing_build_match,
        .action_write = l2l3_multicast_routing_action_write,
        .eg = l2l3_eg,
    },
    [L2L3_TABLE_ACL_POLICY] = {
        // XXX implement this
    },
};

static RockerFlowList *l2l3_flow_fill(struct world *world, uint32_t tbl_id)
{
    struct l2l3_world *lw = world_private(world);

    return flow_sys_flow_fill(lw->fs, tbl_id);
}

static ssize_t l2l3_ig(struct world *world, uint32_t lport,
                       const struct iovec *iov, int iovcnt)
{
    // XXX for now just sent every packet received up on same port
    rx_produce(world, lport, iov, iovcnt);

    struct l2l3_world *lw = world_private(world);
    struct iovec iov_copy[iovcnt + 2];
    struct flow_context fc = {
        .in_lport = lport,
        .iov = iov_copy,
        .iovcnt = iovcnt + 2,
    };

    flow_pkt_parse(&fc, iov, iovcnt);
    flow_ig_tbl(lw->fs, &fc, L2L3_TABLE_INGRESS_PORT);

    return iov_size(iov, iovcnt);
}

static int l2l3_cmd(struct world *world, struct desc_info *info,
                    char *buf, uint16_t cmd,
                    struct rocker_tlv *cmd_info_tlv)
{
    return 0;
}

static void l2l3_default_bridging(struct l2l3_world *lw)
{
    struct flow *flow;
    struct group *group;

    group = group_alloc(lw->fs);
    group->id = 1;
//    group->type = GROUP_TYPE_L2_INTERFACE;
    group->action.out_lport = 0x00000000;
    group->action.pop_vlan_tag = true;
    group_add(group);

    /* Use dlft VLAN bridging for now for VLAN 100 */
    flow = flow_alloc(lw->fs, flow_sys_another_cookie(lw->fs), 0, 0, 0);
    flow->key.tbl_id = L2L3_TABLE_BRIDGING;
    flow->key.width = FLOW_KEY_WIDTH(eth.dst);
    flow->key.eth.vlan_id = htons(100);
    memset(flow->mask.eth.dst.a, 0xff, sizeof(flow->mask.eth.dst.a));
    flow->action.goto_tbl = L2L3_TABLE_ACL_POLICY;
    flow->action.write.group_id = 1;
    flow_add(flow);
}

static void l2l3_default_vlan(struct l2l3_world *lw)
{
    uint32_t fp_ports = rocker_fp_ports(world_rocker(lw->world));
    struct flow *flow;
    uint32_t lport;

    /* untagged pkts from physical ports goto VLAN 100 */
    for (lport = 1; lport <= fp_ports; lport++) {
        flow = flow_alloc(lw->fs, flow_sys_another_cookie(lw->fs), 0, 0, 0);
        flow->key.tbl_id = L2L3_TABLE_VLAN;
        flow->key.width = FLOW_KEY_WIDTH(eth.vlan_id);
        flow->key.in_lport = lport;
        flow->mask.eth.vlan_id = htons(VLAN_VID_MASK);
        flow->action.goto_tbl = L2L3_TABLE_TERMINATION_MAC;
        flow->action.apply.new_vlan_id = htons(100);
        flow_add(flow);
    }
}

static void l2l3_default_ig_port(struct l2l3_world *lw)
{
    struct flow *flow;

    /* pkts from physical ports goto VLAN tbl */
    flow = flow_alloc(lw->fs, flow_sys_another_cookie(lw->fs), 0, 0, 0);
    flow->key.tbl_id = L2L3_TABLE_INGRESS_PORT;
    flow->key.width = FLOW_KEY_WIDTH(tbl_id);
    flow->key.in_lport = 0x00000000;
    flow->mask.in_lport = ROCKER_FP_PORTS_MAX + 1;
    flow->action.goto_tbl = L2L3_TABLE_VLAN;
    flow_add(flow);
}

static int l2l3_world_init(struct world *world)
{
    struct l2l3_world *lw = world_private(world);

    lw->world = world;
    lw->fs = flow_sys_alloc(world, l2l3_tbl_ops);
    if (!lw->fs)
        return -ENOMEM;

    l2l3_default_ig_port(lw);
    l2l3_default_vlan(lw);
    l2l3_default_bridging(lw);

    return 0;
}

static void l2l3_world_uninit(struct world *world)
{
    struct l2l3_world *lw = world_private(world);

    flow_sys_free(lw->fs);
}

static struct world_ops l2l3_ops = {
    .init = l2l3_world_init,
    .uninit = l2l3_world_uninit,
    .ig = l2l3_ig,
    .cmd = l2l3_cmd,
    .flow_fill = l2l3_flow_fill,
};

struct world *l2l3_world_alloc(struct rocker *r)
{
    return world_alloc(r, sizeof(struct l2l3_world),
                       ROCKER_WORLD_TYPE_L2L3, &l2l3_ops);
}
