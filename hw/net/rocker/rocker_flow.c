/*
 * QEMU rocker switch emulation - common flow processing support
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
#include "rocker_flow.h"

struct flow_sys {
    GHashTable *flow_tbl;
    GHashTable *group_tbl;
    struct flow_tbl_ops *tbl_ops;
    struct world *world;
};

size_t group_tbl_size(struct flow_sys *fs)
{
    return g_hash_table_size(fs->group_tbl);
}

static struct group *group_find(struct flow_sys *fs, uint16_t id)
{
    return g_hash_table_lookup(fs->group_tbl, &id);
}

int group_add(struct group *group)
{
    struct group *next = group_find(group->fs, group->action.next_id);

    if (group_find(group->fs, group->id))
        return -EEXIST;

    /* group's action next group can't be self */
    if (group->action.next_id == group->id)
        return -EINVAL;

#if 0
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
#endif

    g_hash_table_insert(group->fs->group_tbl, &group->id, group);

    if (next)
        next->ref_count++;

    return 0;
}

#if 0
static int group_mod(struct group *group)
{
    struct group *old_group = group_find(group->fs, group->id);

    if (!old_group)
        return -ENOENT;

    // XXX

    return 0;
}

static int group_del(struct flow_sys *fs, uint16_t id)
{
    struct group *group = group_find(fs, id);

    if (!group)
        return -ENOENT;

    if (group->ref_count)
        return -EBUSY;

    g_hash_table_remove(group->hash_all, &id);

    return 0;
}

static int group_get_stats(struct flow_sys *fs, uint16_t id)
{
    struct group *group = group_find(fs, id);

    if (!group)
        return -ENOENT;

    // XXX get/return stats

    return 0;
}
#endif

struct group *group_alloc(struct flow_sys *fs)
{
    struct group *group = g_malloc0(sizeof(struct group));

    if (!group)
        return NULL;

    group->fs = fs;

    return group;
}

size_t flow_tbl_size(struct flow_sys *fs)
{
    return g_hash_table_size(fs->flow_tbl);
}

struct flow *flow_find(struct flow_sys *fs, uint64_t cookie)
{
    return g_hash_table_lookup(fs->flow_tbl, &cookie);
}

int flow_add(struct flow *flow)
{
    g_hash_table_insert(flow->fs->flow_tbl, &flow->cookie, flow);

    return 0;
}

int flow_mod(struct flow *flow)
{
    return 0;
}

void flow_del(struct flow *flow)
{
    g_hash_table_remove(flow->fs->flow_tbl, &flow->cookie);
}

struct flow *flow_alloc(struct flow_sys *fs, uint64_t cookie,
                        uint32_t priority, uint32_t hardtime,
                        uint32_t idletime)
{
    struct flow *flow;

    flow = g_malloc0(sizeof(struct flow));
    if (!flow)
        return NULL;

    flow->fs = fs;
    flow->cookie = cookie;
    flow->priority = priority;
    flow->hardtime = hardtime;
    flow->idletime = idletime;

    return flow;
}

void flow_pkt_parse(struct flow_context *fc, const struct iovec *iov,
                    int iovcnt)
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

void flow_pkt_insert_vlan(struct flow_context *fc)
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

void flow_pkt_strip_vlan(struct flow_context *fc)
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

static void flow_exec_action_set(struct flow_sys *fs, struct flow_context *fc,
                                 struct flow_tbl_ops *ops)
{
    struct flow_action *set = &fc->action_set;
    struct group *group;

    if (set->write.group_id) {
        group = group_find(fs, set->write.group_id);
        if (!group) {
            DPRINTF("flow_exec_action_set group %d not found\n",
                    set->write.group_id);
            return;
        }
        if (group->action.pop_vlan_tag)
            flow_pkt_strip_vlan(fc);
        if (ops->eg)
            ops->eg(fs->world, fc, group->action.out_lport);
    }
}

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

void flow_ig_tbl(struct flow_sys *fs, struct flow_context *fc,
                 uint32_t tbl_id)
{
    struct flow_tbl_ops *ops = &fs->tbl_ops[tbl_id];
    struct flow_match match = { { 0, }, };
    struct flow *flow;

    if (ops->build_match)
        ops->build_match(fc, &match);
    else
        return;

    g_hash_table_foreach(fs->flow_tbl, flow_match, &match);

    flow = match.best;

    if (!flow) {
        if (ops->miss)
            ops->miss(fs, fc);
        return;
    }

    if (ops->action_apply)
        ops->action_apply(fc, flow);

    if (ops->action_write)
        ops->action_write(fc, flow);

    if (flow->action.goto_tbl)
        flow_ig_tbl(fs, fc, flow->action.goto_tbl);
    else
        flow_exec_action_set(fs, fc, ops);
}

uint64_t flow_sys_another_cookie(struct flow_sys *fs)
{
    uint64_t cookie;

    do {
        cookie = 0x8000000000000000 | g_random_int();
    } while (flow_find(fs, cookie));

    return cookie;
}

struct flow_sys *flow_sys_alloc(struct world *world,
                                struct flow_tbl_ops *tbl_ops)
{
    struct flow_sys *fs;

    fs = g_malloc0(sizeof(*fs));
    if (!fs)
        return NULL;

    fs->world = world;
    fs->tbl_ops = tbl_ops;

    fs->flow_tbl = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         NULL, g_free);
    if (!fs->flow_tbl)
        return NULL;

    fs->group_tbl = g_hash_table_new_full(g_int_hash, g_int_equal,
                                          NULL, g_free);
    if (!fs->group_tbl)
        goto err_group_tbl;

    return fs;

err_group_tbl:
    g_hash_table_destroy(fs->flow_tbl);
    return NULL;
}

void flow_sys_free(struct flow_sys *fs)
{
    g_hash_table_destroy(fs->group_tbl);
    g_hash_table_destroy(fs->flow_tbl);
    g_free(fs);
}
