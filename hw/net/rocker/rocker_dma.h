/*
 * QEMU rocker switch emulation - DMA support
 *
 * Copyright (c) 2014 Neil Horman <nhorman@tuxdriver.com>
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


#ifndef _ROCKER_DMA_H_
#define _ROCKER_DMA_H_

#include "hw/hw.h"
#include "hw/pci/pci.h"

#include "rocker_hw.h"
#include "rocker_fp.h"
#include "tlv_parse.h"

struct rocker_dma_ring {
    uint64_t base_addr;
    uint32_t size;
    uint32_t head;
    uint32_t tail;
    uint32_t ctrl;
    uint32_t reserved1;
    uint32_t reserved2;
};

/*
 * Macros to toggle the generation bit
 */
#define DESC_GEN_MASK 0x1000
#define DESC_GEN_BIT(desc) (desc->comp_status & DESC_GEN_MASK)
#define DESC_GEN_TOGGLE(desc) do { \
        (desc)->comp_status = (DESC_GEN_BIT(desc) ^ DESC_GEN_MASK);\
} while(0)

/*
 * Macros to set the completion status
 */
#define DESC_COMP_MASK ~DESC_GEN_MASK
#define desc_set_comp_status(desc, status) do {\
        DESC_GEN_TOGGLE(desc);\
        desc->comp_status |= (status & DESC_COMP_MASK);\
} while(0)

/*
 * Get rocker_dma_ring_get_desc
 * Gets the next dma descriptor on the specified ring
 * Parameters:
 * @d - pci device to which the ring belongs
 * @buf - storage space for the desc to be copied to from pci space
 * @ring - the ring which to find the next descriptor on
 * Returns:
 * @struct rocker_dma_desc - The next descriptor to use for DMA
 * or NULL if none are available;
 */
static inline struct rocker_dma_desc* rocker_dma_ring_get_desc(
                                    PCIDevice *d,
                                    struct rocker_dma_desc *buf,
                                    struct rocker_dma_ring *ring)
{
    if (ring->tail == ring->head)
        buf = NULL;
    else {
        size_t offset = ring->tail * sizeof(struct rocker_dma_desc);
        hwaddr addr = ring->base_addr + offset;
        if (pci_dma_read(d, addr, &buf, sizeof(struct rocker_dma_desc)))
            buf = NULL;
    }

    return buf;
}

/*
 * rocker_dma_tlv_start
 * Resets the descriptor returned from rocker_dma_ring_get_desc so that it is
 * ready for use
 * Parameters:
 * @desc - the descriptor that we are getting ready to populate
 * Returns:
 * Nothing
 * Notes:
 * Assumes that the passed in desc has been returned from a call to
 * rocker_dma_ring_get_desc
 */
static inline void rocker_dma_tlv_start(struct rocker_dma_desc *desc)
{
    desc->tlv_size = 0;
}

/*
 * rocker_dma_tlv_get
 * Access and copied the tlv associated with a given desc into a local
 * buffer for manipulation
 * Parameters:
 * @d - pci device to which the ring belongs
 * @desc - The descriptor to get the tlv for
 * @buf - Buffer memory for the tlv to be copied to
 * Returns
 * A buffer containing the tlv set for the given descriptor or NULL on error
 * Notes:
 * Assumes that the descriptor has been returned from a call to 
 * rocker_dma_ring_get_desc
 * Assumes that the passed in value for buf, points to reserved memory of size
 * desc->tlv_size or greater
 */
static inline struct rocker_dma_tlv* rocker_dma_tlv_get(PCIDevice *d,
                                                struct rocker_dma_desc *desc,
                                                struct rocker_dma_tlv *buf)
{
    if (pci_dma_read(d, desc->buf_addr, buf, desc->tlv_size))
        return NULL;
    return buf;
}

/*
 * rocker_dma_tlv_add
 * Adds a tlv to the tlv descriptor buffer
 * Parameters:
 * @desc - The descriptor that we are adding a tlv to
 * @tlv - The tlv buffer that we are adding to
 * @len - The length of the tlv
 * @val - pointer to the value data to copy into the tlv, or NULL, if no 
 *        copy is requested
 * Returns:
 * Pointer to the tlv that was just populated, or NULL if there was an error
 * Notes:
 * Assumes that the desc pointer was returned from a call to 
 * rocker_dma_ring_get_desc
 * Assumes that the tlv points to a buffer returned from a call to 
 * rocker_dma_tlv_get, specifically to the start of the buffer
 */
static inline struct rocker_dma_tlv* rocker_dma_tlv_add(
                                    struct rocker_dma_desc *desc,
                                    struct rocker_dma_tlv *tlv,
                                    uint32_t type, uint16_t len, void *val)
{
    tlv = (struct rocker_dma_tlv *)(tlv + desc->tlv_size);
    void *data = TLV_DATA(tlv);

    if ((desc->tlv_size + TLV_LENGTH(len) > desc->buf_size))
        return NULL; 

    tlv->type = type;
    tlv->len = TLV_LENGTH(len);
    if (val)
        memcpy(data, val, len);
    desc->tlv_size += tlv->len;
    return tlv; 
}

/*
 * rocker_dma_tlv_copy
 * Helper function to copy scatter gather arrays into a tlv
 * Parameters:
 * @tlv - tlv to populate
 * @src - pointer to src memory to copy
 * @off - Offset into tlv data buffer to start copying to
 * @len - amount of data to copy
 * Returns:
 * 0 on success, or -1 on error
 * Notes:
 * Assumes that the tlv parameter points to the tlv being copied to,
 * which is part of a buffer returned from a call to 
 * rocker_dma_tlv_get
 */
static inline int rocker_dma_tlv_copy(struct rocker_dma_tlv *tlv,
                                        void *src, size_t off,
                                        uint16_t len)
{
    void *dst = TLV_DATA(tlv);

    if ((off + len) > tlv->len)
        return -1;

    memcpy(dst+off, src, len);
    return 0;
    
}

/*
 * rocker_dma_tlv_adjust
 * Helper function to adjust the length of a tlv with reserved size
 * Parameters:
 * @tlv - tlv to adjust
 * @desc - descriptor to which the tlv belongs
 * @len - Adjusted length of the new tlv
 * Notes:
 * TLV being adjusted must not have any tlvs after it in the buffer
 * or unpredictable results will occur
 * Assumes that the tlv parameter points into a buffer that was returned 
 * from a call to rocker_dma_tlv_get
 */
static inline int rocker_dma_tlv_adjust(struct rocker_dma_desc *desc,
                                        struct rocker_dma_tlv *tlv,
                                        uint16_t len)
{
    /* Note add check to ensure we're the last tlv here */
    uint16_t old_len;
    /* Can't grow beyond reserved length */
    if (len > tlv->len)
        return -1;

    old_len = tlv->len;
    tlv->len = TLV_LENGTH(tlv->len - len);

    desc->tlv_size -= (old_len - len);
    return 0;
}

/*
 * rocker_dma_tlv_complete
 * Accepts the tlv buffer returned from rocker_dma_tlv_get, and copies
 * it back to the qemu memory
 * Parameters:
 * @d - PCIDevice to write to
 * @desc - the descriptor to which the tlv buffer belongs
 * @tlv - The tlv buffer to write
 * Returns:
 * 0 on success, or -1 on error
 */
static inline int rocker_dma_tlv_complete(PCIDevice *d,
                                          struct rocker_dma_desc *desc,
                                          struct rocker_dma_tlv *buf)
{
    if (pci_dma_write(d, desc->buf_addr, buf, desc->tlv_size))
        return -1;
    return 0;
}

/*
 * rocker_dma_desc_complete
 * Updates the tail of the dma ring, and writes the descriptors competion status
 * Parameters:
 * @d - The pci device we're writing to
 * @ring - The ring we're updating
 * @desc - the descriptor we're completing
 * @comp_stats - The completion status of the descriptor
 * Returns
 * 0 on success, -1 on failure 
 */
static inline int rocker_dma_desc_complete(PCIDevice *d,
                                            struct rocker_dma_ring *ring,
                                            struct rocker_dma_desc *desc,
                                            uint16_t comp_status)
{
    size_t offset = ring->tail * sizeof(struct rocker_dma_desc);
    hwaddr addr = ring->base_addr + offset;

    /*
     * Advance the tail
     */
    ring->tail = (ring->tail < ring->size) ? ring->tail+1 : 0;

    /*
     * Set the completion status of the new descriptor
     */
    desc_set_comp_status(desc, comp_status);

    /*
     * And write the result to the ring in pci space
     */
    if (pci_dma_write(d, addr, desc, sizeof(struct rocker_dma_desc)))
        return -1;
    return 0;
}


#endif
