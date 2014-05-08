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

#ifndef _ROCKER_L2L3_H_
#define _ROCKER_L2L3_H_

struct rocker;
struct world;

struct world *l2l3_world_alloc(struct rocker *r);

#endif /* _ROCKER_L2L3_H_ */
