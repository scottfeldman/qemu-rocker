#ifndef _ROCKER_FP_H_
#define _ROCKER_FP_H_

#include "net/clients.h"

enum fp_port_backend {
    FP_BACKEND_NONE = 1,
    FP_BACKEND_TAP,
};

/* each front-panel port is a qemu nic, with private configuration */
struct fp_port {
    void *parent;  /* back pointer to parent */
    uint index;
    char *name;
    enum fp_port_backend backend;
    NICState *nic;
    NICConf conf;
};

void fp_port_set_conf(struct fp_port *port, char *sw_name,
                      MACAddr *start_mac, void *parent, uint index);
void fp_port_clear_conf(struct fp_port *port);
int fp_port_set_netdev(struct fp_port *port,
                       enum fp_port_backend backend,
                       char *script, char *downscript);
void fp_port_clear_netdev(struct fp_port *port);
int fp_port_set_nic(struct fp_port *port, const char *type);
void fp_port_clear_nic(struct fp_port *port);

#endif /* _ROCKER_FP_H_ */
