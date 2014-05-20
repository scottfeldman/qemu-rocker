/*
 * QEMU rocker switch emulation - traditional L2/L3 processing support
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
#include "qemu/iov.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_world.h"
#include "rocker_l2l3.h"

struct l2l3_world {
};

static int l2l3_cmd(struct world *world, struct desc_info *info,
                    char *buf, uint16_t cmd,
                    struct rocker_tlv *cmd_info_tlv)
{
    return 0;
}

static ssize_t l2l3_ig(struct world *world, uint32_t lport,
                       const struct iovec *iov, int iovcnt)
{
    // XXX for now just sent every packet received up on same port
    rx_produce(world, lport, iov, iovcnt);

    return iov_size(iov, iovcnt);
}

static int l2l3_world_init(struct world *world)
{
    return 0;
}

static void l2l3_world_uninit(struct world *world)
{
}

static struct world_ops l2l3_ops = {
    .init = l2l3_world_init,
    .uninit = l2l3_world_uninit,
    .ig = l2l3_ig,
    .cmd = l2l3_cmd,
};

struct world *l2l3_world_alloc(struct rocker *r)
{
    return world_alloc(r, sizeof(struct l2l3_world),
                       ROCKER_WORLD_TYPE_L2L3, &l2l3_ops);
}
