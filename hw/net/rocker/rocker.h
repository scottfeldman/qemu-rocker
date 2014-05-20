/*
 * QEMU rocker switch emulation
 *
 * Copyright (c) 2014 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _ROCKER_H_
#define _ROCKER_H_

#if defined (DEBUG_ROCKER)
#  define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "ROCKER: " fmt, ## __VA_ARGS__); } while (0)
#else
static inline GCC_FMT_ATTR(1, 2) int DPRINTF(const char *fmt, ...)
{
    return 0;
}
#endif

#define __le16 uint16_t
#define __le32 uint32_t
#define __le64 uint64_t

#define __be16 uint16_t
#define __be32 uint32_t
#define __be64 uint64_t

struct world;
struct rocker;

int rx_produce(struct world *world, uint32_t lport,
               const struct iovec *iov, int iovcnt);
int rocker_port_eg(struct rocker *r, uint32_t lport,
                   const struct iovec *iov, int iovcnt);
void rocker_update_irq(struct rocker *r);
void rocker_irq_status_append(struct rocker *r, uint32_t irq_status);

#endif /* _ROCKER_H_ */
