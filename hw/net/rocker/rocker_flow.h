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

#ifndef _ROCKER_FLOW_H_
#define _ROCKER_FLOW_H_

/* flow_key stolen mostly from OVS
 *
 * Note: fields that compare with network packet header fields
 * are stored in network order (BE) to avoid per-packet field
 * byte-swaps.
 */

struct flow_key {
    uint32_t in_lport;               /* ingress port */
    uint32_t tunnel_id;              /* overlay tunnel id */
    uint32_t tbl_id;                 /* table id */
    struct {
        __be16 vlan_id;              /* 0 if no VLAN */
        MACAddr src;                 /* ethernet source address */
        MACAddr dst;                 /* ethernet destination address */
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
    int width;                       /* how many uint64_t's in key? */
};

/* Width of key which includes field 'f' in u64s, rounded up */
#define FLOW_KEY_WIDTH(f) \
    ((offsetof(struct flow_key, f) + sizeof(((struct flow_key *)0)->f) + \
      sizeof(uint64_t) - 1) / sizeof(uint64_t))

struct flow_action {
    uint32_t goto_tbl;
    struct {
        uint32_t group_id;
        uint32_t tun_log_lport;
        __be16 vlan_id;
    } write;
    struct {
        __be16 new_vlan_id;
        uint32_t out_lport;
    } apply;
};

struct flow_sys;
struct flow_world;

struct flow {
    struct flow_sys *fs;
    uint32_t priority;
    uint32_t hardtime;
    uint32_t idletime;
    uint64_t cookie;
    struct flow_key key;
    struct flow_key mask;
    struct flow_action action;
    struct {
        uint64_t hits;
        uint32_t duration;
        uint64_t rx_pkts;
        uint64_t tx_pkts;
    } stats;
};

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
    uint32_t in_lport;
    uint32_t tunnel_id;
    struct iovec *iov;
    int iovcnt;
    struct eth_header ethhdr_rewrite;
    struct vlan_header vlanhdr_rewrite;
    struct vlan_header vlanhdr;
    struct flow_pkt_fields fields;
    struct flow_action action_set;
};

struct flow_match {
    struct flow_key value;
    struct flow *best;
};

struct flow *flow_alloc(struct flow_sys *fs, uint64_t cookie,
                        uint32_t priority, uint32_t hardtime,
                        uint32_t idletime);
int flow_add(struct flow *flow);
int flow_mod(struct flow *flow);
void flow_del(struct flow *flow);
struct flow *flow_find(struct flow_sys *fs, uint64_t cookie);
void flow_pkt_parse(struct flow_context *fc, const struct iovec *iov,
                    int iovcnt);
void flow_pkt_insert_vlan(struct flow_context *fc, __be16 vlan_id);
void flow_pkt_strip_vlan(struct flow_context *fc);
void flow_pkt_hdr_reset(struct flow_context *fc);
void flow_pkt_hdr_rewrite(struct flow_context *fc, uint8_t *src_mac,
                          uint8_t *dst_mac, __be16 vlan_id);
void flow_ig_tbl(struct flow_sys *fs, struct flow_context *fc,
                 uint32_t tbl_id);
size_t flow_tbl_size(struct flow_sys *fs);

struct flow_tbl_ops {
    void (*build_match)(struct flow_context *fc, struct flow_match *match);
    void (*hit)(struct flow_sys *fs, struct flow_context *fc,
                struct flow *flow);
    void (*miss)(struct flow_sys *fs, struct flow_context *fc);
    void (*hit_no_goto)(struct flow_sys *fs, struct flow_context *fc);
    void (*action_apply)(struct flow_context *fc, struct flow *flow);
    void (*action_write)(struct flow_context *fc, struct flow *flow);
};

struct group {
    struct flow_sys *fs;
    uint32_t id;
    union {
        struct {
            uint32_t out_lport;
            uint8_t pop_vlan;
        } l2_interface;
        struct {
            uint32_t group_id;
            MACAddr src_mac;
            MACAddr dst_mac;
            __be16 vlan_id;
        } l2_rewrite;
        struct {
            uint16_t group_count;
            uint32_t *group_ids;
        } l2_flood;
    };
};

struct group *group_alloc(struct flow_sys *fs, uint32_t id);
struct group *group_find(struct flow_sys *fs, uint32_t id);
int group_add(struct group *group);
int group_del(struct group *group);
size_t group_tbl_size(struct flow_sys *fs);

RockerFlowList *flow_sys_flow_fill(struct flow_sys *fs, uint32_t tbl_id);
RockerGroupList *flow_sys_group_fill(struct flow_sys *fs, uint32_t tbl_id);
uint64_t flow_sys_another_cookie(struct flow_sys *fs);
struct flow_sys *flow_sys_alloc(struct world *world,
                                struct flow_tbl_ops *tbl_ops);
void flow_sys_free(struct flow_sys *fs);
struct world *flow_sys_world(struct flow_sys *fs);

#endif /* _ROCKER_FLOW_H_ */
