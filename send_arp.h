/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#ifndef _SEND_ARP_H__
#define _SEND_ARP_H__

#include <cstdio>
#include <cstdlib>
#include <stdint.h>

#include <pcap.h>
#include <arpa/inet.h>


namespace xvzd {

enum EthType : uint16_t {
  ARP_TYPE = 0x0806
};

enum ArpOpCode : uint16_t {
  ARP_REQUEST = 0x0001,
  ARP_REPLY   = 0x0002
};

typedef struct packet {
} packet_t;

typedef struct ip : packet_t {
  uint8_t* address[4];
} ip_packet_t;

typedef struct mac : packet_t {
  uint8_t* address[6];
} mac_packet_t;

typedef struct ArpPacket : packet_t {
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
  mac_packet_t dmac;
  mac_packet_t smac;
  EthType      type;
  packet_t     data;
  uint32_t     crc;
} eth_packet_t;

class SendArp {
public:
  SendArp()  {};
  ~SendArp() {}

#ifdef    DEBUG
  void    print(void);
#endif
  void    init(char *interface, char *sender_ip, char *target_ip);
  char*   to_cstring(void);
  void    parse(uint8_t raw_packet);
private:
  char*   interface;
  char*   sender_ip;
  char*   target_ip;

  pcap_t* handle;
  char    errbuf[PCAP_ERRBUF_SIZE];

  arp_packet_t packet;
};

#endif  // _SEND_ARP_H__

}
