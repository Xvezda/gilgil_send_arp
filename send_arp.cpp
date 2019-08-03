/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::printf;
using std::fprintf;
using xvzd::SendArp;

void SendArp::init(char *interface, char *sender_ip, char *target_ip) {
  this->interface = interface;
  this->sender_ip = sender_ip;
  this->target_ip = target_ip;

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "Counldn't open device %s: %s\n", interface, errbuf);
  }
}

#ifdef DEBUG
void SendArp::print() {
  printf("interface:\t%s\n"
         "sender_ip:\t%s\n"
         "target_ip:\t%s\n", interface, sender_ip, target_ip);
}
#endif

char* SendArp::to_cstring() {
  char *ret = nullptr;

  return ret;
}

void SendArp::parse(uint8_t raw_packet) {
}
