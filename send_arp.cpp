/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"
#include "eth_packet.h"


using std::vector;

using std::printf;
using std::fprintf;
using std::strtok;
using std::strtoul;

using xvzd::StatusCode;
using xvzd::Packet;
using xvzd::EthPacket;
using xvzd::EthType;
using xvzd::ArpPacket;
using xvzd::SendArp;


SendArp::SendArp() {}

SendArp::~SendArp() {
  if (handle != nullptr) {
    pcap_close(handle);
    handle = nullptr;
  }
}

StatusCode SendArp::init(char *interface, char *sender_ip, char *target_ip) {
  this->interface = interface;

  this->sender_ip = IpAddress(6, reinterpret_cast<u_char*>(sender_ip));
  this->sender_ip = IpAddress(6, reinterpret_cast<u_char*>(target_ip));

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    return STAT_FAILED;
  }
  return STAT_SUCCESS;
}

char* SendArp::to_cstring() {
  char *ret = nullptr;

  return ret;
}

void SendArp::parse(const u_char* raw_packet) {
  EthPacket eth(const_cast<u_char*>(raw_packet));
  if (eth.get_type() != TYPE_ARP) return;

  ArpPacket* arp = reinterpret_cast<ArpPacket*>(eth.get_data());

#ifdef DEBUG
  printf("[DEBUG]\n");
  printf("sender_address: %s\n",
      String(arp->get_sender_address()).to_cstring());
  printf("target_address: %s\n",
      String(arp->get_target_address()).to_cstring());
  printf("sender_ip: %s\n", String(arp->get_sender_ip()).to_cstring());
  printf("target_ip: %s\n", String(arp->get_target_ip()).to_cstring());
  printf("operation: %s\n",
      (arp->get_operation() == ARP_REQUEST)
      ? "ARP_REQUEST" : "ARP_REPLY");
  printf("-----\n");

  uint8_t *my_mac = SendArp::get_my_mac_addr(interface);
  printf("[DEBUG] %s:%d: %02x %02x %02x %02x %02x %02x\n",
      __FILE__, __LINE__,
      my_mac[0], my_mac[1], my_mac[2],
      my_mac[3], my_mac[4], my_mac[5]);
  printf("\n");
#endif
}

void SendArp::listen() {
  if (handle == nullptr) return;

  struct pcap_pkthdr *header;
  const u_char *raw_packet;
  int res;

  for (int i = 0;; i++) {
    res = pcap_next_ex(handle, &header, &raw_packet);
    if (!res) continue;
    if (res == -1 || res == -2) break;

    parse(raw_packet);
  }
}

void SendArp::send(u_char* packet, size_t size) {
  if (handle == nullptr) return;

  int res = pcap_sendpacket(handle, packet, size);
  if (res != 0) {
    fprintf(stderr, "Couldn't send packet:  %s\n", pcap_geterr(handle));
    return;
  }
}
