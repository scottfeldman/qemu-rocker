/*
 * QEMU rocker switch emulation - TLV parsing and composing
 *
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _ROCKER_TLV_H_
#define _ROCKER_TLV_H_

#define ROCKER_TLV_ALIGNTO 8U
#define ROCKER_TLV_ALIGN(len) \
    (((len) + ROCKER_TLV_ALIGNTO - 1) & ~(ROCKER_TLV_ALIGNTO - 1))
#define ROCKER_TLV_HDRLEN ROCKER_TLV_ALIGN(sizeof(struct rocker_tlv))

/*
 *  <------- ROCKER_TLV_HDRLEN -------> <--- ROCKER_TLV_ALIGN(payload) --->
 * +-----------------------------+- - -+- - - - - - - - - - - - - - -+- - -+
 * |             Header          | Pad |           Payload           | Pad |
 * |     (struct rocker_tlv)     | ing |                             | ing |
 * +-----------------------------+- - -+- - - - - - - - - - - - - - -+- - -+
 *  <--------------------------- tlv->len -------------------------->
 */

static inline struct rocker_tlv *rocker_tlv_next(const struct rocker_tlv *tlv,
                                                 int *remaining)
{
    int totlen = ROCKER_TLV_ALIGN(tlv->len);

    *remaining -= totlen;
    return (struct rocker_tlv *) ((char *) tlv + totlen);
}

static inline int rocker_tlv_ok(const struct rocker_tlv *tlv, int remaining)
{
    return remaining >= (int) ROCKER_TLV_HDRLEN &&
           tlv->len >= ROCKER_TLV_HDRLEN &&
           tlv->len <= remaining;
}

#define rocker_tlv_for_each_attr(pos, head, len, rem) \
    for (pos = head, rem = len; \
         rocker_tlv_ok(pos, rem); \
         pos = rocker_tlv_next(pos, &(rem)))

static inline int rocker_tlv_attr_size(int payload)
{
    return ROCKER_TLV_HDRLEN + payload;
}

static inline int rocker_tlv_total_size(int payload)
{
    return ROCKER_TLV_ALIGN(rocker_tlv_attr_size(payload));
}

static inline int rocker_tlv_padlen(int payload)
{
    return rocker_tlv_total_size(payload) - rocker_tlv_attr_size(payload);
}

static inline int rocker_tlv_type(const struct rocker_tlv *tlv)
{
    return tlv->type;
}

static inline void *rocker_tlv_data(const struct rocker_tlv *tlv)
{
    return (char *) tlv + ROCKER_TLV_HDRLEN;
}

static inline int rocker_tlv_len(const struct rocker_tlv *tlv)
{
    return tlv->len - ROCKER_TLV_HDRLEN;
}

static inline uint8_t rocker_tlv_get_u8(const struct rocker_tlv *tlv)
{
    return *(uint8_t *) rocker_tlv_data(tlv);
}

static inline uint16_t rocker_tlv_get_u16(const struct rocker_tlv *tlv)
{
    return le16_to_cpu(*(uint16_t *) rocker_tlv_data(tlv));
}

static inline uint32_t rocker_tlv_get_u32(const struct rocker_tlv *tlv)
{
    return le16_to_cpu(*(uint32_t *) rocker_tlv_data(tlv));
}

static inline void rocker_tlv_parse(struct rocker_tlv **tb, int maxtype,
                                    const char *buf, int buf_len)
{
    const struct rocker_tlv *tlv;
    const struct rocker_tlv *head = (const struct rocker_tlv *) buf;
    int rem;

    memset(tb, 0, sizeof(struct rocker_tlv *) * (maxtype + 1));

    rocker_tlv_for_each_attr(tlv, head, buf_len, rem) {
        uint32_t type = rocker_tlv_type(tlv);

        if (type > 0 && type <= maxtype)
            tb[type] = (struct rocker_tlv *) tlv;
    }
}

static inline void rocker_tlv_parse_nested(struct rocker_tlv **tb,
                                           int maxtype,
                                           const struct rocker_tlv *tlv)
{
    rocker_tlv_parse(tb, maxtype, rocker_tlv_data(tlv), rocker_tlv_len(tlv));
}

static inline struct rocker_tlv *
rocker_tlv_start(char *buf, int buf_pos)
{
    return (struct rocker_tlv *) (buf + buf_pos);
}

static inline void rocker_tlv_put(char *buf, int *buf_pos,
                                  int attrtype, int attrlen, const void *data)
{
    int total_size = rocker_tlv_total_size(attrlen);
    struct rocker_tlv *tlv;

    tlv = rocker_tlv_start(buf, *buf_pos);
    *buf_pos += total_size;
    tlv->type = attrtype;
    tlv->len = rocker_tlv_attr_size(attrlen);
    memcpy(rocker_tlv_data(tlv), data, attrlen);
    memset((char *) tlv + tlv->len, 0, rocker_tlv_padlen(attrlen));
}

static inline void rocker_tlv_put_u8(char *buf, int *buf_pos,
                                     int attrtype, uint8_t value)
{
    rocker_tlv_put(buf, buf_pos, attrtype, sizeof(uint8_t), &value);
}

static inline void rocker_tlv_put_u16(char *buf, int *buf_pos,
                                      int attrtype, uint16_t value)
{
    value = cpu_to_le16(value);
    rocker_tlv_put(buf, buf_pos, attrtype, sizeof(uint16_t), &value);
}

static inline void rocker_tlv_put_u32(char *buf, int *buf_pos,
                                      int attrtype, uint32_t value)
{
    value = cpu_to_le32(value);
    rocker_tlv_put(buf, buf_pos, attrtype, sizeof(uint32_t), &value);
}

static inline struct rocker_tlv *rocker_tlv_nest_start(char *buf, int *buf_pos,
                                                       int attrtype)
{
    struct rocker_tlv *start = rocker_tlv_start(buf, *buf_pos);

    rocker_tlv_put(buf, buf_pos, attrtype, 0, NULL);
    return start;
}

static inline void rocker_tlv_nest_end(char *buf, int *buf_pos,
                                       struct rocker_tlv *start)
{
    start->len = (char * ) rocker_tlv_start(buf, *buf_pos) - (char *) start;
}

static inline void rocker_tlv_nest_cancel(char *buf, int *buf_pos,
                                          struct rocker_tlv *start)
{
    *buf_pos = (char *) start - buf;
}

#endif
