/*
 * QEMU rocker switch emulation - Descriptor ring support
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


#ifndef _ROCKER_DESC_H_
#define _ROCKER_DESC_H_

#include "rocker_hw.h"

struct rocker;
struct desc_ring;
struct desc_info;

typedef int (desc_ring_consume)(struct rocker *r, struct desc_info *info);

uint16_t desc_buf_size(struct desc_info *info);
uint16_t desc_tlv_size(struct desc_info *info);
char *desc_get_buf(struct desc_info *info, bool read_only);
int desc_set_buf(struct desc_info *info, size_t tlv_size);
struct desc_ring *desc_get_ring(struct desc_info *info);

int desc_ring_index(struct desc_ring *ring);
bool desc_ring_set_base_addr(struct desc_ring *ring, uint64_t base_addr);
uint64_t desc_ring_get_base_addr(struct desc_ring *ring);
bool desc_ring_set_size(struct desc_ring *ring, uint32_t size);
uint32_t desc_ring_get_size(struct desc_ring *ring);
bool desc_ring_set_head(struct desc_ring *ring, uint32_t new);
uint32_t desc_ring_get_head(struct desc_ring *ring);
uint32_t desc_ring_get_tail(struct desc_ring *ring);
void desc_ring_set_ctrl(struct desc_ring *ring, uint32_t val);
bool desc_ring_ret_credits(struct desc_ring *ring, uint32_t credits);
uint32_t desc_ring_get_credits(struct desc_ring *ring);

struct desc_info *desc_ring_fetch_desc(struct desc_ring *ring);
bool desc_ring_post_desc(struct desc_ring *ring, int status);

void desc_ring_set_consume(struct desc_ring *ring,
                           desc_ring_consume *consume, unsigned vector);
unsigned desc_ring_get_msix_vector(struct desc_ring *ring);
struct desc_ring *desc_ring_alloc(struct rocker *r, int index);
void desc_ring_free(struct desc_ring *ring);
void desc_ring_reset(struct desc_ring *ring);

#endif
