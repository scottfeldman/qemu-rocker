/*
 * QEMU rocker switch emulation - switch worlds
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

#include "qemu/iov.h"

#include "rocker.h"
#include "rocker_world.h"

struct rocker;

struct world {
    struct rocker *rocker;
    struct world_ops *ops;
};

ssize_t world_ingress(struct world *world, uint16_t lport,
                      const struct iovec *iov, int iovcnt)
{
    if (world->ops->ig)
        return world->ops->ig(world, lport, iov, iovcnt);

    return iov_size(iov, iovcnt);
}

int world_do_cmd(struct world *world, struct rocker_tlv **tlvs)
{
    if (world->ops->cmd)
        return world->ops->cmd(world, tlvs);

    return -ENOTSUP;
}

struct world *world_alloc(struct rocker *rocker, size_t sizeof_private,
                          struct world_ops *ops)
{
    struct world *w = g_malloc0(sizeof(struct world) + sizeof_private);

    if (w) {
        w->rocker = rocker;
        w->ops = ops;
        if (w->ops->init)
            w->ops->init(w);
    }

    return w;
}

void world_free(struct world *world)
{
    if (world->ops->uninit)
        world->ops->uninit(world);
}

void *world_private(struct world *world)
{
    return world + 1;
}

struct rocker *world_rocker(struct world *world)
{
    return world->rocker;
}
