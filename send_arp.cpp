/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::printf;
using std::fprintf;
using xvzd::SendArp;

SendArp::SendArp() {
}

SendArp::~SendArp() {
  pcap_close(handle);
}

void SendArp::init(char *interface, char *sender_ip, char *target_ip) {
  this->interface = interface;

  this->sender_ip = ip_parser(sender_ip);
  this->target_ip = ip_parser(target_ip);

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

void SendArp::parse(const u_char* raw_packet) {
  eth_packet_t eth(const_cast<u_char*>(raw_packet));
}

void SendArp::listen() {
  if (handle == nullptr) return;

  struct pcap_pkthdr *header;
  const u_char *raw_packet;
  int res;

  for (;;) {
    res = pcap_next_ex(handle, &header, &raw_packet);
    if (!res) return;
    if (res == -1 || res == -2) break;

    parse(raw_packet);
  }
}
