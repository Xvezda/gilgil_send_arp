#ifndef _SEND_ARP_H
#define _SEND_ARP_H

#include <cstdio>
#include <cstdlib>

namespace xvzd {

class SendArp {
public:
  SendArp(char *interface, char *sender_ip, char *target_ip)
    : interface(interface), sender_ip(sender_ip), target_ip(target_ip) {}
  ~SendArp() {}

  void print(void);
private:
  char *interface;
  char *sender_ip;
  char *target_ip;
};

#endif  // _SEND_ARP_H

}
