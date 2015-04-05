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
/*
 * Common functionality that can be leveraged by all P4 worlds
 */
#include <stdarg.h>
#include "net/eth.h"
#include "qemu/iov.h"
#include "qemu/timer.h"
#include "qmp-commands.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_fp.h"
#include "rocker_tlv.h"
#include "rocker_world.h"
#include "rocker_desc.h"
#include "rocker_p4_rmt.h"
#include "rocker_p4_l2l3_features.h"
#include "rocker_p4_l2l3_enums.h"
#include "rocker_p4_l2l3_tables.h"
#include "rocker_p4_l2l3_tables_if.h"
#include "rocker_p4_l2l3.h"
#include "rocker_p4_common.h"

unsigned char *rocker_p4_iov_to_buffer(const struct iovec *iov, int iovcnt);
static int rocker_p4_rmt_table_cmd (struct p4_rmt_world *p4_rmt, 
                                    struct desc_info *info,
                                    char *buf, unsigned short cmd,
                                    RockerTlv **tlvs);

unsigned char *
rocker_p4_iov_to_buffer(const struct iovec *iov, int iovcnt)
{
    // convert iov to a single contiguous buffer for p4 model
    int len = 0;
    unsigned char *buf = NULL;

    len = iov_size(iov, iovcnt);
    DPRINTF("convert %d iovs to a buffer of len %d\n", iovcnt, len);
    buf = malloc(len);
    if (buf == NULL) {
        DPRINTF("Cannot allocate buffer\n");
        return buf;
    }
    iov_to_buf(iov, iovcnt, 0, buf, len);
    return buf;
}


void rocker_p4_rmt_tx (int eg_port1, void *pkt, int len, int ig_port1)
{
    struct iovec iov;
    int    iovcnt = 1;
    struct rocker *rocker;
    struct world *w;
    unsigned int fp_ig_port;

    w = rocker_world_from_pport(ig_port1);
    struct p4_rmt_world *p4_rmt = world_private(w);
    rocker = p4_rmt->rocker;

    fp_port_from_pport((unsigned int)ig_port1, &fp_ig_port);

    DPRINTF("rocker_p4_rmt_tx to port %d, len %d.... \n", eg_port1, len);
    if (eg_port1 == 0) {
        DPRINTF("rocker_p4_rmt_tx DROP .... \n");
        free (pkt);
        return;
    }
    // convert the packet to iov
    iov.iov_len = len;
    iov.iov_base = pkt;
    if (rocker == NULL) {
        DPRINTF("\"rocker\" not found\n");
        return;
    }
    if (w == NULL) {
        DPRINTF("P4-RMT world not found\n");
        return;
    }
    // check for sup port
    if (p4_rmt->is_cpu_port(eg_port1)) {
        DPRINTF("rocker_p4_rmt_tx to CPU from ingress port %d, len %d.... \n", 
                    ig_port1, len);
        rx_produce(w, ig_port1, &iov, iovcnt);
        return;
    }
    // call qemu_send to send out on switch port
    rocker_port_eg(rocker, eg_port1, &iov, iovcnt);
    return;
}

static int rocker_p4_rmt_table_cmd (struct p4_rmt_world *p4_rmt, 
                            struct desc_info *info,
                            char *buf, unsigned short cmd,
                            RockerTlv **tlvs)
{
    unsigned int    table_id;
    unsigned char   *entry;
    if (tlvs[ROCKER_TLV_P4_RMT_INFO_TABLE_ID] == NULL ||
        tlvs[ROCKER_TLV_P4_RMT_INFO_TABLE_ENTRY] == NULL) {
        DPRINTF("Missing TLVs\n");
        return 0;
    }
        
    table_id = rocker_tlv_get_u32(tlvs[ROCKER_TLV_P4_RMT_INFO_TABLE_ID]);
    entry = rocker_tlv_data(tlvs[ROCKER_TLV_P4_RMT_INFO_TABLE_ENTRY]);

    DPRINTF("p4_rmt_table_cmd for table %d\n", table_id);

    if (!p4_rmt->is_table_valid(table_id)) {
        DPRINTF("p4_rmt_table_cmd for invalide table %d\n", table_id);
        return 0;
    }

    switch (cmd) {
        case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_ADD:
            // check if fn is provided
            if (p4_rmt->table_ops[table_id].add) {
                p4_rmt->table_ops[table_id].add(entry);
            }
            break;
        case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_MOD:
        case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_DEL:
            break;
        case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_DEFAULT_ACTION:
        {
            unsigned int action_id = rocker_tlv_get_u32(
                            tlvs[ROCKER_TLV_P4_RMT_INFO_TABLE_ENTRY]);
            // XXX - add support for action data for default action
            unsigned char data[4] = {0,0,0,0}; // HACK
            if (p4_rmt->table_ops[table_id].default_action) {
                p4_rmt->table_ops[table_id].default_action((int)action_id, 
                                                            data);
            }
            break;
        }
    }
    return 0;
}

ssize_t rocker_p4_rmt_ig (World *world, unsigned int pport,
                            const struct iovec *iov, int iovcnt)
{
    int pkt_len = iov_size(iov, iovcnt);
    unsigned int port = pport;  // model uses pports (1-N)
    struct p4_rmt_world *p4_rmt = world_private(world);

    // ingress pipeline
    DPRINTF("p4_rmt_ingress port %d, len %d .... \n", port, pkt_len);

    // convert iov to a pkt buffer
    unsigned char *buf = rocker_p4_iov_to_buffer(iov, iovcnt);
    if (buf == NULL) {
        return 0;
    }
    p4_rmt->process_pkt(port, buf, pkt_len);
    return iov_size(iov, iovcnt);
}

void rocker_p4_rmt_uninit (World *world)
{
    // XXX rmt uninit
    return;
}

int rocker_p4_rmt_init (World *world)
{
    struct p4_rmt_world *p4_rmt = world_private(world);
    p4_rmt->world = world;
    p4_rmt->rocker = world_rocker(world);

    DPRINTF("p4_rmt_init ... \n");
    rmt_init();
    // debug logging
    rmt_logger_set((p4_logging_f)printf);
    rmt_log_level_set(P4_LOG_LEVEL_TRACE);
    // register transmit function
    rmt_transmit_register(rocker_p4_rmt_tx);
    return 0;
}

int rocker_p4_rmt_cmd(World *world, struct desc_info *info,
                      char *buf, unsigned short cmd, RockerTlv *cmd_info_tlv)
{
    struct p4_rmt_world *p4_rmt = world_private(world);
    RockerTlv *tlvs[ROCKER_TLV_P4_RMT_INFO_MAX + 1];

    rocker_tlv_parse_nested(tlvs, ROCKER_TLV_P4_RMT_INFO_MAX, cmd_info_tlv);
    DPRINTF("Rocker P4 CMD %d\n", (int)cmd);

    switch (cmd) {
    case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_ADD:
    case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_MOD:
    case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_ENTRY_DEL:
    case ROCKER_TLV_CMD_TYPE_P4_RMT_TABLE_DEFAULT_ACTION:
        return rocker_p4_rmt_table_cmd(p4_rmt, info, buf, cmd, tlvs);
    default:
        return -ROCKER_ENOTSUP;
    }
}
