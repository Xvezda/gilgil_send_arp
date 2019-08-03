#include "send_arp.h"


using std::printf;
using xvzd::SendArp;

void SendArp::print(void) {
  printf("interface:\t%s\n"
         "sender_ip:\t%s\n"
         "target_ip:\t%s\n", interface, sender_ip, target_ip);
}
