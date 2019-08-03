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

#include <pcap.h>
#include <arpa/inet.h>

/*
#define MAC_UNKNOWN   0x000000000000
#define MAC_BROADCAST 0xffffffffffff
*/

enum EthType : uint16_t {
  TYPE_IPV4 = 0x0800,
  TYPE_ARP  = 0x0806
};

enum ArpOpCode : uint16_t {
  ARP_REQUEST = 0x0001,
  ARP_REPLY   = 0x0002
};

// Base struct
typedef struct packet {
} packet_t;

typedef struct ip : packet_t {
  ip() {}
  ip(const ip& src) : size(src.size), address(src.address) {}
  ip(uint8_t size, uint8_t* address) : size(size), address(address) {}
  ~ip() { delete[] address; }
  uint8_t  size;
  uint8_t* address;
} ip_packet_t;

typedef struct mac : packet_t {
  mac() {}
  mac(uint8_t size, uint8_t* address) : size(size), address(address) {}
  ~mac() { delete[] address; }
  uint8_t  size;
  uint8_t* address;
} mac_packet_t;

typedef struct ArpPacket : packet_t {
  ArpPacket() {}
  ArpPacket(u_char* raw_packet) {
  }
  uint16_t     hardware_type;
  uint16_t     protocol_type;
  uint8_t      hardware_size;
  uint8_t      protocol_size;
  ArpOpCode    operation;
  mac_packet_t sender_address;
  ip_packet_t  sender_ip;
  mac_packet_t target_address;
  ip_packet_t  target_ip;
} arp_packet_t;

typedef struct EthPacket : packet_t {
  EthPacket() {}
  EthPacket(u_char* raw_packet) {
    assert(raw_packet != nullptr);

    u_char* cursor = raw_packet;

    dmac = mac_packet_t(6, cursor);
    smac = mac_packet_t(6, &cursor[6]);

    uint16_t type = ntohs(reinterpret_cast<uint16_t&>(cursor[12]));
    assert(EthType::TYPE_ARP == type);
    type = EthType::TYPE_ARP;
  }
  mac_packet_t dmac;
  mac_packet_t smac;
  EthType      type;
  packet_t     data;
  uint32_t     crc;
} eth_packet_t;

namespace xvzd {

class SendArp {
public:
  SendArp();
  ~SendArp();

#ifdef         DEBUG
  void         print(void);
#endif
  void         init(char *interface, char *sender_ip, char *target_ip);
  char*        to_cstring(void);
  void         listen(void);
  void         parse(const u_char* raw_packet);

  uint16_t     get_hardware_type(void);
  uint16_t     get_protocol_type(void);
  uint8_t      get_hardware_size(void);
  uint8_t      get_protocol_size(void);
  ArpOpCode    get_operation(void);
  mac_packet_t get_sender_address(void);
  ip_packet_t  get_sender_ip(void);
  mac_packet_t get_target_address(void);
  ip_packet_t  get_target_ip(void);

private:
  char*        interface;
  ip_packet_t  sender_ip;
  ip_packet_t  target_ip;

  pcap_t*      handle;
  char         errbuf[PCAP_ERRBUF_SIZE];

  arp_packet_t packet;
  u_char*      raw_packet;

  ip_packet_t  ip_parser(char* ip_address) {
    ip_packet_t ret;
    size_t cnt = 0;

    uint8_t i = 0;
    char *token, *address = ip_address;

    // Count number of dots
    for (char* ptr = address; *ptr; ptr++) {
      if (*ptr == '.') ++cnt;
    }
    // Number when tokenized
    cnt = cnt + 1;
    // Initialize return object
    ret.size = cnt;
    ret.address = new uint8_t[cnt];

    // Tokenize to parse values
    token = std::strtok(address, ".");
    do {
      char *tmp;
      ret.address[i] = std::strtoul(token, &tmp, 10);
      ++i;
    } while ((token = std::strtok(NULL, ",")));

    return ret;
  }
};

#endif  // _SEND_ARP_H__

}
