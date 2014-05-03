/*
 * QEMU rocker switch emulation - Descriptor ring support
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


#ifndef _ROCKER_DESC_H_
#define _ROCKER_DESC_H_

#include "rocker_hw.h"

struct rocker;
struct desc_ring;

typedef int (desc_ring_consume)(struct rocker *r, struct rocker_desc *desc);

char *desc_get_buf(struct rocker_desc *desc, PCIDevice *dev, bool tlv_only,
                   size_t *size);
void desc_put_buf(char *buf);
int desc_set_buf(struct rocker_desc *desc, PCIDevice *dev, char *buf,
                 size_t tlv_size);

bool desc_ring_empty(struct desc_ring *ring);
bool desc_ring_full(struct desc_ring *ring);
bool desc_ring_set_base_addr(struct desc_ring *ring, uint64_t base_addr);
uint64_t desc_ring_get_base_addr(struct desc_ring *ring);
bool desc_ring_set_size(struct desc_ring *ring, uint32_t size);
uint32_t desc_ring_get_size(struct desc_ring *ring);
int desc_ring_set_head(struct desc_ring *ring, uint32_t new);
uint32_t desc_ring_get_head(struct desc_ring *ring);
uint32_t desc_ring_get_tail(struct desc_ring *ring);
bool desc_ring_set_ctrl(struct desc_ring *ring, uint32_t new);
uint32_t desc_ring_get_ctrl(struct desc_ring *ring);

struct rocker_desc *desc_ring_fetch_desc(struct desc_ring *ring);
void desc_ring_post_desc(struct desc_ring *ring, struct rocker_desc *desc,
                         int status);

struct desc_ring *desc_ring_alloc(struct rocker *r, int index,
                                  desc_ring_consume *consume);
void desc_ring_free(struct desc_ring *ring);

#endif
