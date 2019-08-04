/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"

using std::vector;

using xvzd::Packet;
using xvzd::EthPacket;
using xvzd::EthType;


vector<uint8_t> EthPacket::get_dmac() {
  vector<uint8_t> mac_address;

  return mac_address;
}

vector<uint8_t> EthPacket::get_smac() {
  vector<uint8_t> mac_address;

  return mac_address;
}

EthType EthPacket::get_type() {
  uint16_t _type = get_uint16_t(type);

  switch (_type) {
  case TYPE_ARP:
    return TYPE_ARP;
  case TYPE_IPV4:
    return TYPE_IPV4;
  default:
    return TYPE_UNKNOWN;
  }
}

Packet* EthPacket::get_data() {
  switch (get_type()) {
  case TYPE_ARP:
    return new ArpPacket(data);
  case TYPE_IPV4:
  default:
    return new Packet();
  }
}


