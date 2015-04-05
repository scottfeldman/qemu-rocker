/*
 * QEMU rocker switch emulation - PCI device - P4 support
 *
 * Copyright (c) 2015 Parag Bhide <parag.bhide@barefootnetworks.com>
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

#ifndef _ROCKER_P4_COMMON_H_
#define _ROCKER_P4_COMMON_H_

typedef bool (p4_is_cpu_port_fn_t)(int port);
typedef bool (p4_is_table_valid_fn_t)(unsigned int table_id);
typedef int  (p4_rmt_process_pkt_fn_t)(int ingress, void *pkt, int len);

typedef struct p4_rmt_world {
    World  *world;
    Rocker *rocker;
    // XXX add all the tables etc ???
    p4_is_cpu_port_fn_t     *is_cpu_port;
    p4_is_table_valid_fn_t  *is_table_valid;
    p4_rmt_process_pkt_fn_t *process_pkt;
    p4_rmt_table_ops_t      *table_ops;    // array of table ops
} p4_rmt_world_t;

void    rocker_p4_rmt_tx (int eg_port1, void *pkt, int len, int ig_port1);
ssize_t rocker_p4_rmt_ig (World *world, unsigned int pport,
                            const struct iovec *iov, int iovcnt);
int     rocker_p4_rmt_cmd(World *world, struct desc_info *info,
                      char *buf, unsigned short cmd, RockerTlv *cmd_info_tlv);
int     rocker_p4_rmt_init (World *world);
void    rocker_p4_rmt_uninit (World *world);

#endif // _ROCKER_P4_COMMON_H_
