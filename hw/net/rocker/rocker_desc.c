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

struct desc_info;

struct desc_ring {
    hwaddr base_addr;
    uint32_t size;
    uint32_t head;
    uint32_t tail;
    uint32_t ctrl;
    uint32_t credits;
    struct rocker *r;
    struct desc_info *info;
    int index;
    desc_ring_consume *consume;
    unsigned msix_vector;
};

struct desc_info {
    struct desc_ring *ring;
    struct rocker_desc desc;
    char *buf;
    size_t buf_size;
};

uint16_t desc_buf_size(struct desc_info *info)
{
    return le16_to_cpu(info->desc.buf_size);
}

uint16_t desc_tlv_size(struct desc_info *info)
{
    return le16_to_cpu(info->desc.tlv_size);
}

char *desc_get_buf(struct desc_info *info, bool read_only)
{
    PCIDevice *dev = PCI_DEVICE(info->ring->r);
    size_t size = read_only ? le16_to_cpu(info->desc.tlv_size) :
                              le16_to_cpu(info->desc.buf_size);

    if (size > info->buf_size) {
        info->buf = g_realloc(info->buf, size);
        info->buf_size = size;
    }

    if (!info->buf)
        return NULL;

    if (pci_dma_read(dev, le64_to_cpu(info->desc.buf_addr), info->buf, size))
        return NULL;

    return info->buf;
}

int desc_set_buf(struct desc_info *info, size_t tlv_size)
{
    PCIDevice *dev = PCI_DEVICE(info->ring->r);

    if (tlv_size > info->buf_size) {
        DPRINTF("ERROR: trying to write more to desc buf than it can hold buf_size %ld tlv_size %ld\n",
                info->buf_size, tlv_size);
        return -EMSGSIZE;
    }

    info->desc.tlv_size = cpu_to_le16(tlv_size);
    pci_dma_write(dev, le64_to_cpu(info->desc.buf_addr), info->buf, tlv_size);

    return 0;
}

struct desc_ring *desc_get_ring(struct desc_info *info)
{
    return info->ring;
}

int desc_ring_index(struct desc_ring *ring)
{
    return ring->index;
}

static bool desc_ring_empty(struct desc_ring *ring)
{
    return ring->head == ring->tail;
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
    int i;

    if (size < 2 || size > 0x10000 || (size & (size - 1))) {
        DPRINTF("ERROR: ring[%d] size (%d) not a power of 2 or in range [2, 64K]\n",
                ring->index, size);
        return false;
    }

    for (i = 0; i < ring->size; i++)
        if (ring->info[i].buf)
            g_free(ring->info[i].buf);

    ring->size = size;
    ring->head = ring->tail = 0;

    ring->info = g_realloc(ring->info, size * sizeof(struct desc_info));
    if (!ring->info)
        return false;

    memset(ring->info, 0, size * sizeof(struct desc_info));

    for (i = 0; i < size; i++)
        ring->info[i].ring = ring;

    return true;
}

uint32_t desc_ring_get_size(struct desc_ring *ring)
{
    return ring->size;
}

static struct desc_info *desc_read(struct desc_ring *ring, uint32_t index)
{
    PCIDevice *dev = PCI_DEVICE(ring->r);
    struct desc_info *info = &ring->info[index];
    hwaddr addr = ring->base_addr + (sizeof(struct rocker_desc) * index);

    pci_dma_read(dev, addr, &info->desc, sizeof(info->desc));

    return info;
}

static void desc_write(struct desc_ring *ring, uint32_t index)
{
    PCIDevice *dev = PCI_DEVICE(ring->r);
    struct desc_info *info = &ring->info[index];
    hwaddr addr = ring->base_addr + (sizeof(struct rocker_desc) * index);

    pci_dma_write(dev, addr, &info->desc, sizeof(info->desc));
}

static bool desc_ring_base_addr_check(struct desc_ring *ring)
{
    if (!ring->base_addr) {
        DPRINTF("ERROR: ring[%d] not-initialized desc base address!\n",
                ring->index);
        return false;
    }
    return true;
}

static struct desc_info *__desc_ring_fetch_desc(struct desc_ring *ring)
{
    return desc_read(ring, ring->tail);
}

struct desc_info *desc_ring_fetch_desc(struct desc_ring *ring)
{
    if (desc_ring_empty(ring) || !desc_ring_base_addr_check(ring))
        return NULL;

    return desc_read(ring, ring->tail);
}

static bool __desc_ring_post_desc(struct desc_ring *ring, int err)
{
    uint16_t comp_err = 0x8000 | (uint16_t)-err;
    struct desc_info *info = &ring->info[ring->tail];

    info->desc.comp_err = cpu_to_le16(comp_err);
    desc_write(ring, ring->tail);
    ring->tail = (ring->tail + 1) % ring->size;

    /* return true if starting credit count */

    return (ring->credits++ == 0);
}

bool desc_ring_post_desc(struct desc_ring *ring, int err)
{
    if (desc_ring_empty(ring)) {
        DPRINTF("ERROR: ring[%d] trying to post desc to empty ring\n",
                ring->index);
        return false;
    }

    if (!desc_ring_base_addr_check(ring))
        return false;

    return __desc_ring_post_desc(ring, err);
}

static bool ring_pump(struct desc_ring *ring)
{
    struct desc_info *info;
    bool primed = false;
    int err;

    /* If the ring has a consumer, call consumer for each
     * desc starting at tail and stopping when tail reaches
     * head (the empty ring condition).
     */

    if (ring->consume) {
        while (ring->head != ring->tail) {
            info = __desc_ring_fetch_desc(ring);
            err = ring->consume(ring->r, info);
            if (__desc_ring_post_desc(ring, err))
                primed = true;
        }
    }

    return primed;
}

bool desc_ring_set_head(struct desc_ring *ring, uint32_t new)
{
    uint32_t tail = ring->tail;
    uint32_t head = ring->head;

    if (!desc_ring_base_addr_check(ring))
        return false;

    if (new >= ring->size) {
        DPRINTF("ERROR: trying to set head (%d) past ring[%d] size (%d) \n",
                new, ring->index, ring->size);
        return false;
    }

    if (((head < tail) && ((new >= tail) || (new < head))) ||
        ((head > tail) && ((new >= tail) && (new < head)))) {
        DPRINTF("ERROR: trying to wrap ring[%d] (head %d, tail %d, new head %d)\n",
                ring->index, head, tail, new);
        return false;
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

void desc_ring_set_ctrl(struct desc_ring *ring, uint32_t val)
{
}

bool desc_ring_ret_credits(struct desc_ring *ring, uint32_t credits)
{
    if (credits > ring->credits) {
        DPRINTF("ERROR: trying to return more credits (%d) than are outstanding (%d)\n",
                credits, ring->credits);
        ring->credits = 0;
        return false;
    }

    ring->credits -= credits;

    /* return true if credits are still outstanding */

    return ring->credits > 0;
}

uint32_t desc_ring_get_credits(struct desc_ring *ring)
{
    return ring->credits;
}

void desc_ring_set_consume(struct desc_ring *ring,
                           desc_ring_consume *consume, unsigned vector)
{
    ring->consume = consume;
    ring->msix_vector = vector;
}

unsigned desc_ring_get_msix_vector(struct desc_ring *ring)
{
    return ring->msix_vector;
}

struct desc_ring *desc_ring_alloc(struct rocker *r, int index)
{
    struct desc_ring *ring;

    ring = g_malloc0(sizeof(struct desc_ring));
    if (!ring)
        return NULL;

    ring->r = r;
    ring->index = index;

    return ring;
}

void desc_ring_free(struct desc_ring *ring)
{
    if (ring->info)
        g_free(ring->info);
    g_free(ring);
}

void desc_ring_reset(struct desc_ring *ring)
{
    ring->base_addr = 0;
    ring->size = 0;
    ring->head = 0;
    ring->tail = 0;
    ring->ctrl = 0;
    ring->credits = 0;
}
