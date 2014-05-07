/*
 * QEMU rocker switch emulation - front-panel ports
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

#ifndef _ROCKER_FP_H_
#define _ROCKER_FP_H_

#include "net/net.h"
#include "qemu/iov.h"

#define ROCKER_FP_PORTS_MAX 62

enum fp_port_backend {
    FP_BACKEND_NONE = 1,
    FP_BACKEND_TAP,
};

struct rocker;
struct fp_port;
struct world;

int fp_port_eg(struct fp_port *port, const struct iovec *iov, int iovcnt);

bool fp_port_get_link_up(struct fp_port *port);
int fp_port_get_settings(struct fp_port *port, uint32_t *speed,
                         uint8_t *duplex, uint8_t *autoneg,
                         MACAddr macaddr);
int fp_port_set_settings(struct fp_port *port, uint32_t speed,
                         uint8_t duplex, uint8_t autoneg,
                         MACAddr macaddr);
bool fp_port_from_lport(uint16_t lport, uint16_t *port);
void fp_port_set_conf(struct fp_port *port, struct rocker *r, char *sw_name,
                      MACAddr *start_mac, uint index);
void fp_port_clear_conf(struct fp_port *port);
int fp_port_set_netdev(struct fp_port *port,
                       enum fp_port_backend backend,
                       char *script, char *downscript);
void fp_port_clear_netdev(struct fp_port *port);
int fp_port_set_nic(struct fp_port *port, const char *type);
void fp_port_clear_nic(struct fp_port *port);
void fp_port_set_world(struct fp_port *port, struct world *world);
void fp_port_enable(struct fp_port *port);
void fp_port_disable(struct fp_port *port);

struct fp_port *fp_port_alloc(void);
void fp_port_free(struct fp_port *port);

#endif /* _ROCKER_FP_H_ */
