/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#ifndef _SEND_ARP_H__
#define _SEND_ARP_H__


#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <stdint.h>

#include <vector>

#include <pcap.h>
#include <arpa/inet.h>

#include "xvzd_string.h"
using xvzd::String;


enum StatusCode : int {
  STAT_FAILED = -1,
  STAT_SUCCESS = 0,
  STAT_ERROR   = 1,
  STAT_UNKNOWN = 2
};

enum EthType : uint16_t {
  TYPE_UNKNOWN = 0x0000,
  TYPE_IPV4    = 0x0800,
  TYPE_ARP     = 0x0806
};

enum ArpOpCode : uint16_t {
  ARP_REQUEST = 0x0001,
  ARP_REPLY   = 0x0002
};


namespace xvzd {

inline void read_cursor(u_char*& cursor, u_char*& target, size_t size) {
  target = cursor;
  cursor += size;
}

// Base class
class Packet {
public:
  Packet() {}
  Packet(u_char *raw_packet) : data(raw_packet) {}
  ~Packet() {}
protected:
  u_char* data;
};

class AddressPacket : public Packet {
public:
  AddressPacket(size_t _size, u_char *raw_packet) : size(_size) {
    data = raw_packet;
  };
  AddressPacket() {}

  std::vector<uint8_t> get_address(void);
  size_t  get_size(void);
private:
  size_t  size;
};

class IpAddress : public AddressPacket {
public:
  IpAddress(size_t size, u_char *raw_packet) : AddressPacket(size, raw_packet) {}
  IpAddress() {};
  ~IpAddress() {}
};
class MacAddress : public AddressPacket {
public:
  MacAddress(size_t size, u_char *raw_packet) : AddressPacket(size, raw_packet) {}
  MacAddress() {};
  ~MacAddress() {}
};

class ArpPacket : public Packet {
public:
  ArpPacket() {}
  ArpPacket(u_char *raw_packet) {
    assert(raw_packet != nullptr);

    u_char *cursor = raw_packet;

    read_cursor(cursor, hardware_type, 2);
    read_cursor(cursor, protocol_type, 2);
    read_cursor(cursor, hardware_size, 1);
    read_cursor(cursor, protocol_size, 1);

    read_cursor(cursor, operation, 2);

    read_cursor(cursor, sender_address, get_hardware_type());
    read_cursor(cursor, sender_ip, get_protocol_size());
    read_cursor(cursor, target_address, get_hardware_type());
    read_cursor(cursor, target_ip, get_protocol_size());
  }
  ~ArpPacket() {}

  uint16_t             get_hardware_type(void);
  uint16_t             get_protocol_type(void);
  uint8_t              get_hardware_size(void);
  uint8_t              get_protocol_size(void);
  ArpOpCode            get_operation(void);
  std::vector<uint8_t> get_sender_address(void);
  std::vector<uint8_t> get_sender_ip(void);
  std::vector<uint8_t> get_target_address(void);
  std::vector<uint8_t> get_target_ip(void);
private:
  u_char*              hardware_type;
  u_char*              protocol_type;
  u_char*              hardware_size;
  u_char*              protocol_size;
  u_char*              operation;
  u_char*              sender_address;
  u_char*              sender_ip;
  u_char*              target_address;
  u_char*              target_ip;
};

class EthPacket : public Packet {
public:
  EthPacket(u_char *raw_packet) {
    assert(raw_packet != nullptr);

    u_char* cursor = raw_packet;

    read_cursor(cursor, dmac, 6);
    read_cursor(cursor, smac, 6);

    read_cursor(cursor, type, 2);

    // Put all remaining datas
    data = cursor;
  }
  ~EthPacket() {}

  std::vector<uint8_t> get_dmac(void);
  std::vector<uint8_t> get_smac(void);
  EthType              get_type(void);
  Packet*              get_data(void);
private:
  u_char* dmac;
  u_char* smac;
  u_char* type;
  u_char* data;
  u_char* crc;
};


class SendArp {
public:
  SendArp();
  ~SendArp();

#ifdef       DEBUG
  void       print(void);
#endif
  StatusCode init(char *interface, char *sender_ip, char *target_ip);
  char*      to_cstring(void);
  void       listen(void);
  void       parse(const u_char* raw_packet);

  uint16_t   get_hardware_type(void);
  uint16_t   get_protocol_type(void);
  uint8_t    get_hardware_size(void);
  uint8_t    get_protocol_size(void);
  ArpOpCode  get_operation(void);
  MacAddress get_sender_address(void);
  IpAddress  get_sender_ip(void);
  MacAddress get_target_address(void);
  IpAddress  get_target_ip(void);

private:
  char*     interface;
  IpAddress sender_ip;
  IpAddress target_ip;

  pcap_t*   handle;
  char      errbuf[PCAP_ERRBUF_SIZE];

  ArpPacket packet;
};

#endif  // _SEND_ARP_H__


}  // end of namespace
