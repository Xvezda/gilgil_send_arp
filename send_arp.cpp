/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"
#include "eth_packet.h"
#include "arp_packet.h"


using std::vector;

using std::printf;
using std::fprintf;
using std::strtok;
using std::strtoul;

using xvzd::Packet;
using xvzd::EthPacket;
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

  this->sender_ip = IpAddress(4, reinterpret_cast<u_char*>(sender_ip));
  this->target_ip = IpAddress(4, reinterpret_cast<u_char*>(target_ip));

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    return STAT_FAILED;
  }
  return STAT_SUCCESS;
}

void SendArp::parse(const u_char* raw_packet) {
  EthPacket eth(const_cast<u_char*>(raw_packet));
  if (eth.get_type() != TYPE_ARP) return;

  ArpPacket* arp = reinterpret_cast<ArpPacket*>(eth.get_data());

#ifdef DEBUG
  printf("[DEBUG]\n");
  printf("sender_address: %s\n",
      String(arp->get_sender_address()).to_cstr());
  printf("target_address: %s\n",
      String(arp->get_target_address()).to_cstr());
  printf("sender_ip: %s\n", String(arp->get_sender_ip()).to_cstr());
  printf("target_ip: %s\n", String(arp->get_target_ip()).to_cstr());
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

void SendArp::broadcast() {
  const size_t _hardware_size = 6;
  const size_t _protocol_size = 4;

  const size_t total_size = (_hardware_size*2 + 2
      + ArpPacket::get_fixed_header_size()
      + _hardware_size*2 + _protocol_size*2);

  u_char  packet[total_size];
  u_char* cursor = packet;

  const u_char  broadcast_addr[_hardware_size] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
  };
  const u_char* my_mac = SendArp::get_my_mac_addr(interface);

  memcpy(cursor, broadcast_addr, _hardware_size);
  cursor += _hardware_size;
  memcpy(cursor, my_mac, _hardware_size);
  cursor += _hardware_size;

  u_char eth_type[2] = { (TYPE_ARP & 0xff00) >> 8, TYPE_ARP & 0x00ff };
#ifdef DEBUG
  printf("[DEBUG] %s:%d: %02x %02x\n",
      __FILE__, __LINE__, eth_type[0], eth_type[1]);
  printf("[DEBUG] %s:%d: sizeof eth_type: %zu\n",
      __FILE__, __LINE__, sizeof eth_type);
#endif
  memcpy(cursor, eth_type, sizeof eth_type);
  cursor += sizeof eth_type;

  u_char hardware_type[2] = {
    (TYPE_ETH & 0xff00) >> 8, TYPE_ETH & 0x00ff
  };
  memcpy(cursor, hardware_type, sizeof hardware_type);
  cursor += sizeof hardware_type;

  u_char protocol_type[2] = {
    (TYPE_IPV4 & 0xff00) >> 8, TYPE_IPV4 & 0x00ff
  };
  memcpy(cursor, protocol_type, sizeof protocol_type);
  cursor += sizeof protocol_type;

  u_char hardware_size = _hardware_size;
  memcpy(cursor, &hardware_size, sizeof(u_char));
  cursor += sizeof(u_char);

  u_char protocol_size = _protocol_size;
  memcpy(cursor, &protocol_size, sizeof(u_char));
  cursor += sizeof(u_char);

  u_char operation_code[2] = {
    (ARP_REQUEST & 0xff00) >> 8, ARP_REQUEST & 0x00ff
  };
  memcpy(cursor, operation_code, sizeof operation_code);
  cursor += sizeof operation_code;

  //u_char sender_mac[hardware_size];
  memcpy(cursor, my_mac, hardware_size);
  cursor += hardware_size;

  vector<u_char> ip = sender_ip.get_address();
  for (auto i = ip.begin(); i != ip.end(); ++i) {
    memcpy(cursor, &*i, sizeof(u_char));
    cursor += sizeof(u_char);
  }

  u_char target_mac[hardware_size] = {
    // Unknown mac 00:00:00:00:00:00
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  memcpy(cursor, target_mac, hardware_size);
  cursor += hardware_size;

  ip = target_ip.get_address();
  for (auto i = ip.begin(); i != ip.end(); ++i) {
    memcpy(cursor, &*i, sizeof(u_char));
    cursor += sizeof(u_char);
  }

#ifdef DEBUG
  EthPacket  eth = EthPacket(packet);
  ArpPacket* arp = static_cast<ArpPacket*>(eth.get_data());

  printf("[DEBUG]\n");
  printf("+++ BROADCAST +++\n");
  printf("dmac: %s\n", String(eth.get_dmac()).to_cstr());
  printf("smac: %s\n", String(eth.get_smac()).to_cstr());
  printf("-----\n");
  printf("sender_mac: %s\n", String(arp->get_sender_address()).to_cstr());
  printf("sender_ip: %s\n", String(arp->get_sender_ip()).to_cstr());
  printf("target_mac: %s\n", String(arp->get_target_address()).to_cstr());
  printf("target_ip: %s\n", String(arp->get_target_ip()).to_cstr());
  printf("-----\n");
  printf("\n");
#endif
  send(packet, sizeof packet);
}

Packet* SendArp::mimic(u_char* raw_packet, size_t size) {
  Packet* ret = new Packet(raw_packet, size);

  return ret;
}
