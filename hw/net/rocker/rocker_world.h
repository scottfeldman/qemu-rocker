/*
 * QEMU rocker switch emulation - switch worlds
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@gmail.com>
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

#ifndef _ROCKER_WORLD_H_
#define _ROCKER_WORLD_H_

#include "rocker_hw.h"

struct world;
struct rocker;
struct rocker_tlv;
struct desc_info;

enum rocker_world_type {
    ROCKER_WORLD_TYPE_OF_DPA = ROCKER_PORT_MODE_OF_DPA,
    ROCKER_WORLD_TYPE_MAX,
};

typedef int (world_init)(struct world *world);
typedef void (world_uninit)(struct world *world);
typedef ssize_t (world_ig)(struct world *world, uint32_t lport,
                           const struct iovec *iov, int iovcnt);
typedef int (world_cmd)(struct world *world, struct desc_info *info,
                        char *buf, uint16_t cmd,
                        struct rocker_tlv *cmd_info_tlv);
typedef RockerFlowList *(world_flow_fill)(struct world *world,
                                          uint32_t tbl_id);
typedef RockerGroupList *(world_group_fill)(struct world *world,
                                            uint8_t type);

struct world_ops {
    world_init *init;
    world_uninit *uninit;
    world_ig *ig;
    world_cmd *cmd;
    world_flow_fill *flow_fill;
    world_group_fill *group_fill;
};

RockerFlowList *world_do_flow_fill(struct world *world, uint32_t tbl_id);
RockerGroupList *world_do_group_fill(struct world *world, uint8_t type);
ssize_t world_ingress(struct world *world, uint32_t lport,
                      const struct iovec *iov, int iovcnt);
int world_do_cmd(struct world *world, struct desc_info *info,
                 char *buf, uint16_t cmd, struct rocker_tlv *cmd_info_tlv);

struct world *world_alloc(struct rocker *r, size_t sizeof_private,
                          enum rocker_world_type type, struct world_ops *ops);
void world_free(struct world *world);
void world_reset(struct world *world);

void *world_private(struct world *world);
struct rocker *world_rocker(struct world *world);

enum rocker_world_type world_type(struct world *world);
const char *world_name(struct world *world);

#endif /* _ROCKER_WORLD_H_ */
