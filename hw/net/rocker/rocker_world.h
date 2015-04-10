/*
 * QEMU rocker switch emulation - switch worlds
 *
 * Copyright (c) 2014 Scott Feldman <sfeldma@gmail.com>
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

#ifndef _ROCKER_WORLD_H_
#define _ROCKER_WORLD_H_

#include "rocker_hw.h"

enum rocker_world_type {
    ROCKER_WORLD_TYPE_OF_DPA = ROCKER_PORT_MODE_OF_DPA,
    ROCKER_WORLD_TYPE_P4_L2L3 = ROCKER_PORT_MODE_P4_L2L3,
    ROCKER_WORLD_TYPE_MAX,
};

typedef int (world_init)(World *world);
typedef void (world_uninit)(World *world);
typedef ssize_t (world_ig)(World *world, uint32_t pport,
                           const struct iovec *iov, int iovcnt);
typedef int (world_cmd)(World *world, DescInfo *info,
                        char *buf, uint16_t cmd,
                        RockerTlv *cmd_info_tlv);

typedef struct world_ops {
    world_init *init;
    world_uninit *uninit;
    world_ig *ig;
    world_cmd *cmd;
} WorldOps;

ssize_t world_ingress(World *world, uint32_t pport,
                      const struct iovec *iov, int iovcnt);
int world_do_cmd(World *world, DescInfo *info,
                 char *buf, uint16_t cmd, RockerTlv *cmd_info_tlv);

World *world_alloc(Rocker *r, size_t sizeof_private,
                   enum rocker_world_type type, 
                   const char *name, WorldOps *ops);
void world_free(World *world);
void world_reset(World *world);

void *world_private(World *world);
Rocker *world_rocker(World *world);

enum rocker_world_type world_type(World *world);
const char *world_name(World *world);

World *rocker_get_world(Rocker *r, enum rocker_world_type type);
World *rocker_world_from_pport(int pport);

#endif /* _ROCKER_WORLD_H_ */
