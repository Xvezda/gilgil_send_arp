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

#include "xvzd_types.h"
#include "mac_address.h"
#include "ip_address.h"
#include "arp_packet.h"
#include "eth_packet.h"


namespace xvzd {

using std::vector;

enum StatusCode : int {
  STAT_FAILED = -1,
  STAT_SUCCESS = 0,
  STAT_ERROR   = 1,
  STAT_UNKNOWN = 2
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

}  // end of namespace


#endif  // _SEND_ARP_H__
