/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::printf;
using std::fprintf;

using xvzd::Packet;
using xvzd::SendArp;
using xvzd::EthPacket;
using xvzd::ArpPacket;
using xvzd::AddressPacket;

std::vector<uint8_t> AddressPacket::get_address() {
  std::vector<uint8_t> ret;
    uint8_t i = 0;
    char *token;
    u_char* address = data;

    // Tokenize to parse values
    token = std::strtok(reinterpret_cast<char*>(address), ".");
    do {
      char *tmp;
      ret.push_back(std::strtoul(token, &tmp, 10));
      ++i;
    } while ((token = std::strtok(NULL, ",")));

    return ret;

}

std::vector<uint8_t> EthPacket::get_dmac() {
  std::vector<uint8_t> mac_address;

  return mac_address;
}

std::vector<uint8_t> EthPacket::get_smac() {
  std::vector<uint8_t> mac_address;

  return mac_address;
}

uint16_t get_uint32_t(u_char *raw_packet) {
  return ntohl(reinterpret_cast<uint32_t&>(*raw_packet));
}

uint16_t get_uint16_t(u_char *raw_packet) {
  return ntohs(reinterpret_cast<uint16_t&>(*raw_packet));
}

uint16_t ArpPacket::get_hardware_type() {
  return get_uint16_t(hardware_type);
}

uint16_t ArpPacket::get_protocol_type() {
  return get_uint16_t(protocol_type);
}

uint8_t ArpPacket::get_hardware_size() {
  return reinterpret_cast<uint8_t>(*hardware_size);
}

uint8_t ArpPacket::get_protocol_size() {
  return reinterpret_cast<uint8_t>(*protocol_size);
}

EthType EthPacket::get_type() {
  uint16_t _type = get_uint16_t(type);

  switch (_type) {
  case EthType::TYPE_ARP:
    return EthType::TYPE_ARP;
  case EthType::TYPE_IPV4:
    return EthType::TYPE_IPV4;
  default:
    return EthType::TYPE_UNKNOWN;
  }
}

template <typename T>
std::vector<uint8_t> get_address(T from, size_t size) {
  std::vector<uint8_t> address;
  size_t i;
  for (i = 0; i < size; ++i) {
    address.push_back(from[i]);
  }
  return address;
}

std::vector<uint8_t> ArpPacket::get_sender_address() {
  return get_address(sender_address, get_hardware_size());
}

std::vector<uint8_t> ArpPacket::get_sender_ip() {
  return get_address(sender_ip, get_protocol_size());
}

std::vector<uint8_t> ArpPacket::get_target_address() {
  return get_address(target_address, get_hardware_size());
}

std::vector<uint8_t> ArpPacket::get_target_ip() {
  return get_address(target_ip, get_protocol_size());
}

Packet* EthPacket::get_data() {
  switch (get_type()) {
  case EthType::TYPE_ARP:
    return new ArpPacket(data);
  case EthType::TYPE_IPV4:
  default:
    return new Packet();
  }
}

SendArp::SendArp() {
}

SendArp::~SendArp() {
  pcap_close(handle);
}

StatusCode SendArp::init(char *interface, char *sender_ip, char *target_ip) {
  this->interface = interface;

  this->sender_ip = IpAddress(6, reinterpret_cast<u_char*>(sender_ip));
  this->sender_ip = IpAddress(6, reinterpret_cast<u_char*>(target_ip));

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "Counldn't open device %s: %s\n", interface, errbuf);
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
  if (eth.get_type() != EthType::TYPE_ARP) return;

  ArpPacket* arp = reinterpret_cast<ArpPacket*>(eth.get_data());
#ifdef DEBUG
  printf("[DEBUG]\n");
  printf("sender_address: %s\n", String(arp->get_sender_address()).to_cstring());
  printf("target_address: %s\n", String(arp->get_target_address()).to_cstring());
  printf("sender_ip: %s\n", String(arp->get_sender_ip()).to_cstring());
  printf("target_ip: %s\n", String(arp->get_target_ip()).to_cstring());
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
