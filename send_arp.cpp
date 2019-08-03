/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::printf;
using xvzd::SendArp;

#ifdef DEBUG
void SendArp::print(void) {
  printf("interface:\t%s\n"
         "sender_ip:\t%s\n"
         "target_ip:\t%s\n", interface, sender_ip, target_ip);
}
#endif
