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

#include "net/net.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"

#include "rocker.h"
#include "rocker_hw.h"
#include "rocker_desc.h"

struct desc_ring {
    hwaddr base_addr;
    uint32_t size;
    uint32_t head;
    uint32_t tail;
    uint32_t ctrl;
    struct rocker *r;
    struct rocker_desc *backing;
    int index;
    desc_ring_consume *consume;
};

char *desc_get_buf(struct rocker_desc *desc, PCIDevice *dev, bool read_only)
{
    char *buf;
    size_t size = read_only ? le16_to_cpu(desc->tlv_size) :
                              le16_to_cpu(desc->buf_size);

    buf = g_malloc(size);

    if (!buf)
        return NULL;

    if (pci_dma_read(dev, le64_to_cpu(desc->buf_addr), buf, size))
        return NULL;

    return buf;
}

void desc_put_buf(char *buf)
{
    g_free(buf);
}

int desc_set_buf(struct rocker_desc *desc, PCIDevice *dev, char *buf,
                 size_t tlv_size)
{
    if (tlv_size > le16_to_cpu(desc->buf_size)) {
        DPRINTF("ERROR: trying to write more to desc buf than it can hold buf_size %d tlv_size %ld\n",
                le16_to_cpu(desc->buf_size), tlv_size);
        return -EMSGSIZE;
    }

    desc->tlv_size = cpu_to_le16(tlv_size);
    pci_dma_write(dev, le64_to_cpu(desc->buf_addr), buf, tlv_size);

    return 0;
}

bool desc_ring_empty(struct desc_ring *ring)
{
    return ring->head == ring->tail;
}

bool desc_ring_full(struct desc_ring *ring)
{
    return ((ring->head + 1) % ring->size) == ring->tail;
}

bool desc_ring_set_base_addr(struct desc_ring *ring, uint64_t base_addr)
{
    if (base_addr & 0x7) {
        DPRINTF("ERROR: ring[%d] desc base addr (0x%lx) not 8-byte aligned\n",
                ring->index, base_addr);
        return false;
    }

    ring->base_addr = base_addr;

    return true;
}

uint64_t desc_ring_get_base_addr(struct desc_ring *ring)
{
    return ring->base_addr;
}

bool desc_ring_set_size(struct desc_ring *ring, uint32_t size)
{
    if (size < 2 || size > 0x10000 || (size & (size - 1))) {
        DPRINTF("ERROR: ring[%d] size (%d) not a power of 2 or in range [2, 64K]\n",
                ring->index, size);
        return false;
    }

    ring->size = size;
    ring->head = ring->tail = 0;

    ring->backing = g_realloc(ring->backing, size * sizeof(struct rocker_desc));
    if (!ring->backing)
        return false;

    return true;
}

uint32_t desc_ring_get_size(struct desc_ring *ring)
{
    return ring->size;
}

static struct rocker_desc *desc_read(struct desc_ring *ring, uint32_t index)
{
    PCIDevice *dev = (PCIDevice *)ring->r;
    struct rocker_desc *desc = &ring->backing[index];
    hwaddr addr = ring->base_addr + (sizeof(struct rocker_desc) * index);

    pci_dma_read(dev, addr, desc, sizeof(*desc));

    return desc;
}

static void desc_write(struct desc_ring *ring, uint32_t index)
{
    PCIDevice *dev = (PCIDevice *)ring->r;
    struct rocker_desc *desc = &ring->backing[index];
    hwaddr addr = ring->base_addr + (sizeof(struct rocker_desc) * index);

    pci_dma_write(dev, addr, desc, sizeof(*desc));
}

struct rocker_desc *desc_ring_fetch_desc(struct desc_ring *ring)
{
    if (desc_ring_empty(ring))
        return NULL;

    return desc_read(ring, ring->tail);
}

void desc_ring_post_desc(struct desc_ring *ring, struct rocker_desc *desc,
                         int err)
{
    uint16_t comp_err = 0x8000 | (uint16_t)-err;

    if (desc_ring_empty(ring)) {
        DPRINTF("ERROR: ring[%d] trying to post desc to empty ring\n",
                ring->index);
        return;
    }

    desc->comp_err = cpu_to_le16(comp_err);
    desc_write(ring, ring->tail);
    ring->tail = (ring->tail + 1) % ring->size;
}

static int ring_pump(struct desc_ring *ring)
{
    struct rocker_desc *desc;
    int err, consumed = 0;

    /* If the ring has a consumer, call consumer for each
     * desc starting at tail and stopping when tail reaches
     * head (the empty ring condition).
     */

    if (ring->consume) {
        while (ring->head != ring->tail) {
            desc = desc_read(ring, ring->tail);
            err = ring->consume(ring->r, desc);
            desc_ring_post_desc(ring, desc, err);
            consumed++;
        }
    }

    return consumed;
}

int desc_ring_set_head(struct desc_ring *ring, uint32_t new)
{
    uint32_t tail = ring->tail;
    uint32_t head = ring->head;

    if (new >= ring->size) {
        DPRINTF("ERROR: trying to set head (%d) past ring[%d] size (%d) \n",
                new, ring->index, ring->size);
        return 0;
    }

    if (((head < tail) && ((new >= tail) || (new < head))) ||
        ((head > tail) && ((new >= tail) && (new < head)))) {
        DPRINTF("ERROR: trying to wrap ring[%d] (head %d, tail %d, new head %d)\n",
                ring->index, head, tail, new);
        return 0;
    }

    if (new == ring->head)
        DPRINTF("WARNING: setting head (%d) to current head position\n", new);

    ring->head = new;

    return ring_pump(ring);
}

uint32_t desc_ring_get_head(struct desc_ring *ring)
{
    return ring->head;
}

uint32_t desc_ring_get_tail(struct desc_ring *ring)
{
    return ring->tail;
}

bool desc_ring_set_ctrl(struct desc_ring *ring, uint32_t new)
{
    ring->ctrl = new;
    return true;
}

uint32_t desc_ring_get_ctrl(struct desc_ring *ring)
{
    return ring->ctrl;
}

struct desc_ring *desc_ring_alloc(struct rocker *r, int index,
                                  desc_ring_consume *consume)
{
    struct desc_ring *ring;

    ring = g_malloc0(sizeof(struct desc_ring));
    if (!ring)
        return NULL;

    ring->r = r;
    ring->consume = consume;
    ring->index = index;

    return ring;
}

void desc_ring_free(struct desc_ring *ring)
{
    if (ring->backing)
        g_free(ring->backing);
    g_free(ring);
}

void desc_ring_reset(struct desc_ring *ring)
{
    ring->size = 0;
    ring->head = 0;
    ring->tail = 0;
    ring->ctrl = 0;
}
