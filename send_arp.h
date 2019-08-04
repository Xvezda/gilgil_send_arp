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
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>

#include "xvzd_types.h"
#include "mac_address.h"
#include "ip_address.h"
#include "arp_packet.h"
#include "eth_packet.h"


namespace xvzd {

using std::vector;
using std::memcpy;
using std::printf;

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

  StatusCode init(char *interface, char *sender_ip, char *target_ip);
  char*      to_cstring(void);
  void       listen(void);
  void       parse(const u_char* raw_packet);
  void       send(u_char* packet, size_t size);

  uint16_t   get_hardware_type(void);
  uint16_t   get_protocol_type(void);
  uint8_t    get_hardware_size(void);
  uint8_t    get_protocol_size(void);
  ArpOpCode  get_operation(void);
  MacAddress get_sender_address(void);
  IpAddress  get_sender_ip(void);
  MacAddress get_target_address(void);
  IpAddress  get_target_ip(void);

  // Figure out my mac address
  // https://stackoverflow.com/a/1779800
  static u_char* get_my_mac_addr(char* interface) {
    const  size_t size = 6;
    static struct ifreq  s;
    static u_char mac_address[6];
    size_t i;

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, interface);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      for (i = 0; i < size; ++i) {
        mac_address[i] = static_cast<u_char>(s.ifr_addr.sa_data[i]);
      }
    }
    return mac_address;
  }

private:
  char*      interface;
  IpAddress  sender_ip;
  IpAddress  target_ip;

  pcap_t*    handle;
  char       errbuf[PCAP_ERRBUF_SIZE];

  ArpPacket  packet;
};

}  // end of namespace


#endif  // _SEND_ARP_H__

