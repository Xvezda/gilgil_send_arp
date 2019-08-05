/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::vector;

using xvzd::ArpPacket;


template <typename T>
vector<uint8_t> get_address(T from, size_t size) {
  vector<uint8_t> address;
  size_t          i;

  for (i = 0; i < size; ++i) {
    address.push_back(from[i]);
  }
  return address;
}

vector<uint8_t> ArpPacket::get_sender_address() {
  return get_address(sender_address, get_hardware_size());
}

vector<uint8_t> ArpPacket::get_sender_ip() {
  return get_address(sender_ip, get_protocol_size());
}

vector<uint8_t> ArpPacket::get_target_address() {
  return get_address(target_address, get_hardware_size());
}

vector<uint8_t> ArpPacket::get_target_ip() {
  return get_address(target_ip, get_protocol_size());
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

ArpOpCode ArpPacket::get_operation() {
  uint16_t tmp = get_uint16_t(operation);
  switch (tmp) {
  case ARP_REQUEST:
    return ARP_REQUEST;
  case ARP_REPLY:
    return ARP_REPLY;
  default:
    return ARP_UNKNOWN;
  }
}

size_t ArpPacket::get_size() {
  return (ArpPacket::get_fixed_header_size()
      + get_hardware_size() + get_protocol_size());
}


