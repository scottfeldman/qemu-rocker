/*
 * QEMU rocker switch emulation - front-panel ports
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

#ifndef _ROCKER_FP_H_
#define _ROCKER_FP_H_

#include "net/net.h"
#include "qemu/iov.h"

#define ROCKER_FP_PORTS_MAX 62

struct rocker;
struct fp_port;
struct world;

int fp_port_eg(struct fp_port *port, const struct iovec *iov, int iovcnt);

bool fp_port_get_link_up(struct fp_port *port);
void fp_port_get_info(struct fp_port *port, RockerPortList *info);
void fp_port_get_macaddr(struct fp_port *port, MACAddr *macaddr);
void fp_port_set_macaddr(struct fp_port *port, MACAddr *macaddr);
uint8_t fp_port_get_learning(struct fp_port *port);
void fp_port_set_learning(struct fp_port *port, uint8_t learning);
int fp_port_get_settings(struct fp_port *port, uint32_t *speed,
                         uint8_t *duplex, uint8_t *autoneg);
int fp_port_set_settings(struct fp_port *port, uint32_t speed,
                         uint8_t duplex, uint8_t autoneg);
bool fp_port_from_lport(uint32_t lport, uint32_t *port);
struct world *fp_port_get_world(struct fp_port *port);
void fp_port_set_world(struct fp_port *port, struct world *world);
bool fp_port_enabled(struct fp_port *port);
void fp_port_enable(struct fp_port *port);
void fp_port_disable(struct fp_port *port);

struct fp_port *fp_port_alloc(struct rocker *r, char *sw_name,
                              MACAddr *start_mac, uint index,
                              NICPeers *peers);
void fp_port_free(struct fp_port *port);
void fp_port_reset(struct fp_port *port);

#endif /* _ROCKER_FP_H_ */
