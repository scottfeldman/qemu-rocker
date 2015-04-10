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

#include "qemu/iov.h"

#include "rocker.h"
#include "rocker_world.h"

struct world {
    char    *name;
    Rocker  *r;
    enum rocker_world_type type;
    WorldOps *ops;
};

ssize_t world_ingress(World *world, uint32_t pport,
                      const struct iovec *iov, int iovcnt)
{
    if (world->ops->ig) {
        return world->ops->ig(world, pport, iov, iovcnt);
    }

    return iov_size(iov, iovcnt);
}

int world_do_cmd(World *world, DescInfo *info,
                 char *buf, uint16_t cmd, RockerTlv *cmd_info_tlv)
{
    if (world->ops->cmd) {
        return world->ops->cmd(world, info, buf, cmd, cmd_info_tlv);
    }

    return -ROCKER_ENOTSUP;
}

World *world_alloc(Rocker *r, size_t sizeof_private,
                   enum rocker_world_type type, 
                   const char *name, WorldOps *ops)
{
    World *w = g_malloc0(sizeof(World) + sizeof_private);

    if (w) {
        w->r = r;
        w->type = type;
        w->ops = ops;
        if (name) {
            w->name = g_strdup(name);
        } else {
            w->name = g_strdup("unknown-world");
        }
        if (w->ops->init) {
            w->ops->init(w);
        }
    }

    return w;
}

void world_free(World *world)
{
    if (world->ops->uninit) {
        world->ops->uninit(world);
    }
    if (world->name) {
        g_free(world->name);
    }
    g_free(world);
}

void world_reset(World *world)
{
    if (world->ops->uninit) {
        world->ops->uninit(world);
    }
    if (world->ops->init) {
        world->ops->init(world);
    }
}

void *world_private(World *world)
{
    return world + 1;
}

Rocker *world_rocker(World *world)
{
    return world->r;
}

enum rocker_world_type world_type(World *world)
{
    return world->type;
}

const char *world_name(World *world)
{
    if (world) {
        return world->name;
    }
    return "unknown-world";
}
