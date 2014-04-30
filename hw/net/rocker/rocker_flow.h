/*
 * QEMU rocker switch emulation - flow processing support
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

#ifndef _ROCKER_FLOW_H_
#define _ROCKER_FLOW_H_

struct flow_world;
struct fp_port;

int flow_ig(struct fp_port *port, const struct iovec *iov, int iovcnt);

int flow_cmd(struct flow_world *fw, char *cmd_buf, size_t size);

struct flow_world *flow_world_alloc(void);
void flow_world_free(struct flow_world *fw);

#endif /* _ROCKER_FLOW_H_ */
