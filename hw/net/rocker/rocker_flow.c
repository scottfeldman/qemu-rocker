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
#include "rocker_hw.h"
#include "rocker_flow.h"

struct flow_sys {
    GHashTable *flow_tbl;
    GHashTable *group_tbl;
    struct flow_tbl_ops *tbl_ops;
    struct world *world;
};

static const MACAddr zero_mac = { .a = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static const MACAddr ff_mac =   { .a = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };

size_t group_tbl_size(struct flow_sys *fs)
{
    return g_hash_table_size(fs->group_tbl);
}

struct group *group_find(struct flow_sys *fs, uint32_t id)
{
    return g_hash_table_lookup(fs->group_tbl, &id);
}

int group_add(struct group *group)
{
    g_hash_table_insert(group->fs->group_tbl, &group->id, group);

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
#endif

int group_del(struct group *group)
{
    g_hash_table_remove(group->fs->group_tbl, &group->id);

    return 0;
}

#if 0
static int group_get_stats(struct flow_sys *fs, uint32_t id)
{
    struct group *group = group_find(fs, id);

    if (!group)
        return -ENOENT;

    // XXX get/return stats

    return 0;
}
#endif

struct group *group_alloc(struct flow_sys *fs, uint32_t id)
{
    struct group *group = g_malloc0(sizeof(struct group));

    if (!group)
        return NULL;

    group->fs = fs;
    group->id = id;

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
    flow->mask.tbl_id = 0xffffffff;

    return flow;
}

void flow_pkt_hdr_reset(struct flow_context *fc)
{
    struct flow_pkt_fields *fields = &fc->fields;

    fc->iov[0].iov_base = fields->ethhdr;
    fc->iov[0].iov_len = sizeof(struct eth_header);
    fc->iov[1].iov_base = fields->vlanhdr;
    fc->iov[1].iov_len = fields->vlanhdr ? sizeof(struct vlan_header) : 0;
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
        fields->vlanhdr = (struct vlan_header *)(fields->ethhdr + 1);
        fields->h_proto = &fields->vlanhdr->h_proto;
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
    case ETH_P_IPV6:
        sofar += sizeof(struct ip6_header);
        if (iov->iov_len < sofar) {
            DPRINTF("flow_pkt_parse underrun on ip6_header\n");
            return;
        }
        fields->ipv6hdr = (struct ip6_header *)(fields->h_proto + 1);
        break;
    }

    /* To facilitate (potential) VLAN tag insertion, Make a
     * copy of the iov and insert two new vectors at the
     * beginning for eth hdr and vlan hdr.  No data is copied,
     * just the vectors.
     */

    flow_pkt_hdr_reset(fc);

    fc->iov[2].iov_base = fields->h_proto + 1;
    fc->iov[2].iov_len = iov->iov_len - fc->iov[0].iov_len - fc->iov[1].iov_len;

    for (i = 1; i < iovcnt; i++)
        fc->iov[i+2] = iov[i];

    fc->iovcnt = iovcnt + 2;
}

void flow_pkt_insert_vlan(struct flow_context *fc, __be16 vlan_id)
{
    struct flow_pkt_fields *fields = &fc->fields;
    uint16_t h_proto = fields->ethhdr->h_proto;

    if (fields->vlanhdr) {
        DPRINTF("flow_pkt_insert_vlan packet already has vlan\n");
        return;
    }

    fields->ethhdr->h_proto = htons(ETH_P_VLAN);
    fields->vlanhdr = &fc->vlanhdr;
    fields->vlanhdr->h_tci = vlan_id;
    fields->vlanhdr->h_proto = h_proto;
    fields->h_proto = &fields->vlanhdr->h_proto;

    fc->iov[1].iov_base = fields->vlanhdr;
    fc->iov[1].iov_len = sizeof(struct vlan_header);
}

void flow_pkt_strip_vlan(struct flow_context *fc)
{
    struct flow_pkt_fields *fields = &fc->fields;

    if (!fields->vlanhdr)
        return;

    fc->iov[0].iov_len -= sizeof(fields->ethhdr->h_proto);
    fc->iov[1].iov_base = fields->h_proto;
    fc->iov[1].iov_len = sizeof(fields->ethhdr->h_proto);
}

void flow_pkt_hdr_rewrite(struct flow_context *fc, uint8_t *src_mac,
                          uint8_t *dst_mac, __be16 vlan_id)
{
    struct flow_pkt_fields *fields = &fc->fields;

    if (src_mac || dst_mac) {
        memcpy(&fc->ethhdr_rewrite, fields->ethhdr, sizeof(struct eth_header));
        if (src_mac && memcmp(src_mac, zero_mac.a, ETH_ALEN))
            memcpy(fc->ethhdr_rewrite.h_source, src_mac, ETH_ALEN);
        if (dst_mac && memcmp(dst_mac, zero_mac.a, ETH_ALEN))
            memcpy(fc->ethhdr_rewrite.h_dest, dst_mac, ETH_ALEN);
        fc->iov[0].iov_base = &fc->ethhdr_rewrite;
    }

    if (vlan_id && fields->vlanhdr) {
        fc->vlanhdr_rewrite = fc->vlanhdr;
        fc->vlanhdr_rewrite.h_tci = vlan_id;
        fc->iov[1].iov_base = &fc->vlanhdr_rewrite;
    }
}

#if defined (DEBUG_ROCKER)
static void flow_key_dump(struct flow_key *key, struct flow_key *mask)
{
    char buf[512], *b = buf, *mac;

    b += sprintf(b," tbl %2d", key->tbl_id);

    if (key->in_lport || (mask && mask->in_lport)) {
        b += sprintf(b," in_lport %2d", key->in_lport);
        if (mask && mask->in_lport != 0xffffffff)
            b += sprintf(b,"/0x%08x", key->in_lport);
    }

    if (key->tunnel_id || (mask && mask->tunnel_id)) {
        b += sprintf(b," tun %8d", key->tunnel_id);
        if (mask && mask->tunnel_id != 0xffffffff)
            b += sprintf(b,"/0x%08x", key->tunnel_id);
    }

    if (key->eth.vlan_id || (mask && mask->eth.vlan_id)) {
        b += sprintf(b," vlan %4d", ntohs(key->eth.vlan_id));
        if (mask && mask->eth.vlan_id != 0xffff)
            b += sprintf(b,"/0x%04x", ntohs(key->eth.vlan_id));
    }

    if (memcmp(key->eth.src.a, zero_mac.a, ETH_ALEN) ||
        (mask && memcmp(mask->eth.src.a, zero_mac.a, ETH_ALEN))) {
        mac = qemu_mac_strdup_printf(key->eth.src.a);
        b += sprintf(b," src %s", mac);
        g_free(mac);
        if (mask && memcmp(mask->eth.src.a, ff_mac.a, ETH_ALEN)) {
            mac = qemu_mac_strdup_printf(mask->eth.src.a);
            b += sprintf(b,"/%s", mac);
            g_free(mac);
        }
    }

    if (memcmp(key->eth.dst.a, zero_mac.a, ETH_ALEN) ||
        (mask && memcmp(mask->eth.dst.a, zero_mac.a, ETH_ALEN))) {
        mac = qemu_mac_strdup_printf(key->eth.dst.a);
        b += sprintf(b," dst %s", mac);
        g_free(mac);
        if (mask && memcmp(mask->eth.dst.a, ff_mac.a, ETH_ALEN)) {
            mac = qemu_mac_strdup_printf(mask->eth.dst.a);
            b += sprintf(b,"/%s", mac);
            g_free(mac);
        }
    }

    if (key->eth.type || (mask && mask->eth.type)) {
        b += sprintf(b," type 0x%04x", ntohs(key->eth.type));
        if (mask && mask->eth.type != 0xffff)
            b += sprintf(b,"/0x%04x", ntohs(mask->eth.type));
        switch (ntohs(key->eth.type)) {
        case 0x0800:
        case 0x86dd:
            if (key->ip.proto || (mask && mask->ip.proto)) {
                b += sprintf(b, " ip proto %2d", key->ip.proto);
                if (mask && mask->ip.proto != 0xff)
                    b += sprintf(b, "/0x%02x", mask->ip.proto);
            }
            if (key->ip.tos || (mask && mask->ip.tos)) {
                b += sprintf(b, " ip tos %2d", key->ip.tos);
                if (mask && mask->ip.tos != 0xff)
                    b += sprintf(b, "/0x%02x", mask->ip.tos);
            }
            break;
        }
        switch (ntohs(key->eth.type)) {
        case 0x0800:
            if (key->ipv4.addr.dst || (mask && mask->ipv4.addr.dst)) {
                b += sprintf(b, " dst %s",
                    inet_ntoa(*(struct in_addr *)&key->ipv4.addr.dst));
                if (mask)
                    b += sprintf(b, "/%d", mask2prefix(mask->ipv4.addr.dst));
            }
            break;
        }
    }

    DPRINTF("%s\n", buf);
}
#else
#define flow_key_dump(k, m)
#endif

static void _flow_match(void *key, void *value, void *user_data)
{
    struct flow *flow = value;
    struct flow_match *match = user_data;
    uint64_t *k = (uint64_t *)&flow->key;
    uint64_t *m = (uint64_t *)&flow->mask;
    uint64_t *v = (uint64_t *)&match->value;
    int i;

    if (flow->key.tbl_id == match->value.tbl_id)
        flow_key_dump(&flow->key, &flow->mask);

    if (flow->key.width > match->value.width)
        return;

    for (i = 0; i < flow->key.width; i++, k++, m++, v++)
        if ((~*k & *m & *v) | (*k & *m & ~*v))
            return;

    DPRINTF("match\n");

    if (!match->best ||
        flow->priority > match->best->priority ||
        flow->lpm > match->best->lpm)
        match->best = flow;
}

struct flow *flow_match(struct flow_sys *fs, struct flow_match *match)
{
    DPRINTF("\nnew search\n");
    flow_key_dump(&match->value, NULL);

    g_hash_table_foreach(fs->flow_tbl, _flow_match, match);

    return match->best;
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

    flow = flow_match(fs, &match);
    if (!flow) {
        if (ops->miss)
            ops->miss(fs, fc);
        return;
    }

    flow->stats.hits++;

    if (ops->action_apply)
        ops->action_apply(fc, flow);

    if (ops->action_write)
        ops->action_write(fc, flow);

    if (ops->hit)
        ops->hit(fs, fc, flow);

    if (flow->action.goto_tbl)
        flow_ig_tbl(fs, fc, flow->action.goto_tbl);
    else if (ops->hit_no_goto)
        ops->hit_no_goto(fs, fc);

    /* drop packet */
}

struct flow_fill_context {
    RockerFlowList *list;
    uint32_t tbl_id;
};

static void flow_fill(void *cookie, void *value, void *user_data)
{
    struct flow *flow = value;
    struct flow_key *key = &flow->key;
    struct flow_key *mask = &flow->mask;
    struct flow_fill_context *flow_context = user_data;
    RockerFlowList *new;
    RockerFlow *nflow;
    RockerFlowKey *nkey;
    RockerFlowMask *nmask;
    RockerFlowAction *naction;

    if (flow_context->tbl_id != -1 &&
        flow_context->tbl_id != key->tbl_id)
        return;

    new = g_malloc0(sizeof(*new));
    nflow = new->value = g_malloc0(sizeof(*nflow));
    nkey = nflow->key = g_malloc0(sizeof(*nkey));
    nmask = nflow->mask = g_malloc0(sizeof(*nmask));
    naction = nflow->action = g_malloc0(sizeof(*naction));

    nflow->cookie = flow->cookie;
    nflow->hits = flow->stats.hits;
    nkey->priority = flow->priority;
    nkey->tbl_id = key->tbl_id;

    if (key->in_lport || mask->in_lport) {
        nkey->has_in_lport = true;
        nkey->in_lport = key->in_lport;
    }

    if (nkey->has_in_lport && mask->in_lport != 0xffffffff) {
        nmask->has_in_lport = true;
        nmask->in_lport = mask->in_lport;
    }

    if (key->eth.vlan_id || mask->eth.vlan_id) {
        nkey->has_vlan_id = true;
        nkey->vlan_id = ntohs(key->eth.vlan_id);
    }

    if (nkey->has_vlan_id && mask->eth.vlan_id != 0xffff) {
        nmask->has_vlan_id = true;
        nmask->vlan_id = ntohs(mask->eth.vlan_id);
    }

    if (key->tunnel_id || mask->tunnel_id) {
        nkey->has_tunnel_id = true;
        nkey->tunnel_id = key->tunnel_id;
    }

    if (nkey->has_tunnel_id && mask->tunnel_id != 0xffffffff) {
        nmask->has_tunnel_id = true;
        nmask->tunnel_id = mask->tunnel_id;
    }

    if (memcmp(key->eth.src.a, zero_mac.a, ETH_ALEN) ||
        memcmp(mask->eth.src.a, zero_mac.a, ETH_ALEN)) {
        nkey->has_eth_src = true;
        nkey->eth_src = qemu_mac_strdup_printf(key->eth.src.a);
    }

    if (nkey->has_eth_src && memcmp(mask->eth.src.a, ff_mac.a, ETH_ALEN)) {
        nmask->has_eth_src = true;
        nmask->eth_src = qemu_mac_strdup_printf(mask->eth.src.a);
    }

    if (memcmp(key->eth.dst.a, zero_mac.a, ETH_ALEN) ||
        memcmp(mask->eth.dst.a, zero_mac.a, ETH_ALEN)) {
        nkey->has_eth_dst = true;
        nkey->eth_dst = qemu_mac_strdup_printf(key->eth.dst.a);
    }

    if (nkey->has_eth_dst && memcmp(mask->eth.dst.a, ff_mac.a, ETH_ALEN)) {
        nmask->has_eth_dst = true;
        nmask->eth_dst = qemu_mac_strdup_printf(mask->eth.dst.a);
    }

    if (key->eth.type) {

        nkey->has_eth_type = true;
        nkey->eth_type = ntohs(key->eth.type);

        switch (ntohs(key->eth.type)) {
        case 0x0800:
        case 0x86dd:
            if (key->ip.proto || mask->ip.proto) {
                nkey->has_ip_proto = true;
                nkey->ip_proto = key->ip.proto;
            }
            if (nkey->has_ip_proto && mask->ip.proto != 0xff) {
                nmask->has_ip_proto = true;
                nmask->ip_proto = mask->ip.proto;
            }
            if (key->ip.tos || mask->ip.tos) {
                nkey->has_ip_tos = true;
                nkey->ip_tos = key->ip.tos;
            }
            if (nkey->has_ip_tos && mask->ip.tos != 0xff) {
                nmask->has_ip_tos = true;
                nmask->ip_tos = mask->ip.tos;
            }
            break;
        }

        switch (ntohs(key->eth.type)) {
        case 0x0800:
            if (key->ipv4.addr.dst || mask->ipv4.addr.dst) {
                char *dst = inet_ntoa(*(struct in_addr *)&key->ipv4.addr.dst);
                int dst_len = mask2prefix(mask->ipv4.addr.dst);
                nkey->has_ip_dst = true;
                nkey->ip_dst = g_strdup_printf("%s/%d", dst, dst_len);
            }
            break;
        }
    }

    if (flow->action.goto_tbl) {
        naction->has_goto_tbl = true;
        naction->goto_tbl = flow->action.goto_tbl;
    }

    if (flow->action.write.group_id) {
        naction->has_group_id = true;
        naction->group_id = flow->action.write.group_id;
    }

    if (flow->action.apply.new_vlan_id) {
        naction->has_new_vlan_id = true;
        naction->new_vlan_id = flow->action.apply.new_vlan_id;
    }

    new->next = flow_context->list;
    flow_context->list = new;
}

RockerFlowList *flow_sys_flow_fill(struct flow_sys *fs, uint32_t tbl_id)
{
    struct flow_fill_context fill_context = {
        .list = NULL,
        .tbl_id = tbl_id,
    };

    g_hash_table_foreach(fs->flow_tbl, flow_fill, &fill_context);

    return fill_context.list;
}

struct group_fill_context {
    RockerGroupList *list;
    uint32_t tbl_id;
};

static void group_fill(void *key, void *value, void *user_data)
{
    struct group *group = value;
    struct group_fill_context *flow_context = user_data;
    RockerGroupList *new;
    RockerGroup *ngroup;
    struct uint32List *id;
    int i;

    if (flow_context->tbl_id != 9 &&
        flow_context->tbl_id != ROCKER_GROUP_TYPE_GET(group->id))
        return;

    new = g_malloc0(sizeof(*new));
    ngroup = new->value = g_malloc0(sizeof(*ngroup));

    ngroup->id = group->id;

    ngroup->type = ROCKER_GROUP_TYPE_GET(group->id);

    switch (ngroup->type) {
        case ROCKER_OF_DPA_GROUP_TYPE_L2_INTERFACE:
            ngroup->has_vlan_id = true;
            ngroup->vlan_id = ROCKER_GROUP_VLAN_GET(group->id);
            ngroup->has_lport = true;
            ngroup->lport = ROCKER_GROUP_PORT_GET(group->id);
            ngroup->has_out_lport = true;
            ngroup->out_lport = group->l2_interface.out_lport;
            ngroup->has_pop_vlan = true;
            ngroup->pop_vlan = group->l2_interface.pop_vlan;
            break;
        case ROCKER_OF_DPA_GROUP_TYPE_L2_REWRITE:
            ngroup->has_index = true;
            ngroup->index = ROCKER_GROUP_INDEX_LONG_GET(group->id);
            ngroup->has_group_id = true;
            ngroup->group_id = group->l2_rewrite.group_id;
            if (group->l2_rewrite.vlan_id) {
                ngroup->has_set_vlan_id = true;
                ngroup->set_vlan_id = ntohs(group->l2_rewrite.vlan_id);
            }
            break;
            if (memcmp(group->l2_rewrite.src_mac.a, zero_mac.a, ETH_ALEN)) {
                ngroup->has_set_eth_src = true;
                ngroup->set_eth_src =
                    qemu_mac_strdup_printf(group->l2_rewrite.src_mac.a);
            }
            if (memcmp(group->l2_rewrite.dst_mac.a, zero_mac.a, ETH_ALEN)) {
                ngroup->has_set_eth_dst = true;
                ngroup->set_eth_dst =
                    qemu_mac_strdup_printf(group->l2_rewrite.dst_mac.a);
            }
        case ROCKER_OF_DPA_GROUP_TYPE_L2_FLOOD:
        case ROCKER_OF_DPA_GROUP_TYPE_L2_MCAST:
            ngroup->has_vlan_id = true;
            ngroup->vlan_id = ROCKER_GROUP_VLAN_GET(group->id);
            ngroup->has_index = true;
            ngroup->index = ROCKER_GROUP_INDEX_GET(group->id);
            for (i = 0; i < group->l2_flood.group_count; i++) {
                ngroup->has_group_ids = true;
                id = g_malloc0(sizeof(*id));
                id->value = group->l2_flood.group_ids[i];
                id->next = ngroup->group_ids;
                ngroup->group_ids = id;
            }
            break;
    }

    new->next = flow_context->list;
    flow_context->list = new;
}

RockerGroupList *flow_sys_group_fill(struct flow_sys *fs, uint32_t tbl_id)
{
    struct group_fill_context fill_context = {
        .list = NULL,
        .tbl_id = tbl_id,
    };

    g_hash_table_foreach(fs->group_tbl, group_fill, &fill_context);

    return fill_context.list;
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

struct world *flow_sys_world(struct flow_sys *fs)
{
    return fs->world;
}
