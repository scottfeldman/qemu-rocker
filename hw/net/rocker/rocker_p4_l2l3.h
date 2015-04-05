/*
 * QEMU rocker switch emulation - P4 L2L3 pipeline support
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

#ifndef _ROCKER_P4_L2L3_H_
#define _ROCKER_P4_L2L3_H_

World *p4_l2l3_world_alloc(Rocker *r);

#endif /* _ROCKER_P4_L2L3_H_ */
