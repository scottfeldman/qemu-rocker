/*
 * QEMU rocker switch emulation
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




/*
 * Top level parsing macro definitions
 * Unashamedly stolen from linux/netlink.h and updated to be a bit more
 * legible and useful here
 */

#define TLV_ALIGNTO   8U
#define TLVDATA_ALIGN(len) ( ((len)+TLV_ALIGNTO-1) & ~(TLV_ALIGNTO-1) )
#define TLV_HDRLEN (sizeof(struct rocker_dma_tlv))
#define TLV_LENGTH(len) ((len) + TLV_HDRLEN)
#define TLV_SPACE(len) TLV_ALIGN(TLV_LENGTH(len))
#define TLV_DATA(tlv)  ((void*)(((char*)tlv) + TLV_LENGTH(0)))
#define TLV_NEXT(tlv,len)      ((len) -= TLV_ALIGN((tlv)->len), \
                                  (struct rocker_dma_tlv*)(((char*)(tlv)) + \
				TLVDATA_ALIGN((tlv)->len)))
#define TLV_OK(tlv,len) ((len) >= (int)sizeof(struct rocker_dma_tlv) && \
                           (tlv)->len >= sizeof(struct rocker_dma_tlv) && \
                           (tlv)->len <= (len))
#define TLV_PAYLOAD(nlh,len) ((tlv)->len - TLV_SPACE((len)))
