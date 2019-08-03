/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#ifndef _SEND_ARP_H
#define _SEND_ARP_H

#include <cstdio>
#include <cstdlib>
#include <stdint.h>

namespace xvzd {

typedef struct ArpPacket {
  uint8_t *dmac[6];
  uint8_t *smac[6];
} arppck_t;

class SendArp {
public:
  SendArp(char *interface, char *sender_ip, char *target_ip)
    : interface(interface), sender_ip(sender_ip), target_ip(target_ip) {}
  ~SendArp() {}

#ifdef DEBUG
  void print(void);
#endif
private:
  char *interface;
  char *sender_ip;
  char *target_ip;
};

#endif  // _SEND_ARP_H

}
