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

#include "qemu/iov.h"
#include "qmp-commands.h"

#include "rocker.h"
#include "rocker_world.h"

struct rocker;

struct world {
    struct rocker *r;
    enum rocker_world_type type;
    struct world_ops *ops;
};

ssize_t world_ingress(struct world *world, uint32_t lport,
                      const struct iovec *iov, int iovcnt)
{
    if (world->ops->ig) {
        return world->ops->ig(world, lport, iov, iovcnt);
    }

    return iov_size(iov, iovcnt);
}

int world_do_cmd(struct world *world, struct desc_info *info,
                 char *buf, uint16_t cmd, struct rocker_tlv *cmd_info_tlv)
{
    if (world->ops->cmd) {
        return world->ops->cmd(world, info, buf, cmd, cmd_info_tlv);
    }

    return -ENOTSUP;
}

struct world *world_alloc(struct rocker *r, size_t sizeof_private,
                          enum rocker_world_type type, struct world_ops *ops)
{
    struct world *w = g_malloc0(sizeof(struct world) + sizeof_private);

    if (w) {
        w->r = r;
        w->type = type;
        w->ops = ops;
        if (w->ops->init) {
            w->ops->init(w);
        }
    }

    return w;
}

void world_free(struct world *world)
{
    if (world->ops->uninit) {
        world->ops->uninit(world);
    }
    g_free(world);
}

void world_reset(struct world *world)
{
    if (world->ops->uninit) {
        world->ops->uninit(world);
    }
    if (world->ops->init) {
        world->ops->init(world);
    }
}

void *world_private(struct world *world)
{
    return world + 1;
}

struct rocker *world_rocker(struct world *world)
{
    return world->r;
}

enum rocker_world_type world_type(struct world *world)
{
    return world->type;
}

const char *world_name(struct world *world)
{
    switch (world->type) {
    case ROCKER_WORLD_TYPE_OF_DPA:
        return "OF_DPA";
    default:
        return "unknown";
    }
}
