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


#ifndef _TLV_PARSE_H_
#define _TLV_PARSE_H_

/*
 * Top level parsing macro definitions
 * Unashamedly stolen from linux/netlink.h and updated to be a bit more
 * legible and useful here
 */

#define TLV_ALIGNTO   8U
#define TLVDATA_ALIGN(len) ( ((len)+TLV_ALIGNTO-1) & ~(TLV_ALIGNTO-1) )
#define TLV_HDRLEN (sizeof(struct rocker_tlv))
#define TLV_LENGTH(len) ((len) + TLV_HDRLEN)
#define TLV_NEXT(tlv)     (struct rocker_tlv*)(((char*)(tlv)) + \
				TLVDATA_ALIGN(le16_to_cpu((tlv)->len)))
#define TLV_TYPE(tlv) (le32_to_cpu((tlv)->type))
#define TLV_SIZE(tlv) (le16_to_cpu((tlv)->len) - TLV_HDRLEN)

static inline struct rocker_tlv *tlv_start(char *buf, uint32_t type,
                                           size_t size)
{
    struct rocker_tlv *tlv = (struct rocker_tlv *)buf;

    tlv->type = cpu_to_le32(type);
    tlv->len = cpu_to_le16(TLV_LENGTH(size));

    return tlv;
}

static inline struct rocker_tlv *tlv_add(struct rocker_tlv *prev,
                                         uint32_t type, size_t size)
{
    struct rocker_tlv *tlv = TLV_NEXT(prev);

    tlv->type = cpu_to_le32(type);
    tlv->len = cpu_to_le16(TLV_LENGTH(size));

    return tlv;
}

static inline bool tlv_parse(const char *buf, size_t tlv_size,
                             struct rocker_tlv **tlvs, int max)
{
    struct rocker_tlv *tlv = (struct rocker_tlv *)buf;
    int i, cur = 0;

    for (i = 0; i < max; i++) {
        if (cur == tlv_size)
            break;
        *(tlvs++) = tlv;
        tlv = TLV_NEXT(tlv);
        cur = (int)((char *)tlv - buf);
        if (cur > tlv_size)
            return false;
    }

    *tlvs = NULL;

    return true;
}

#endif
