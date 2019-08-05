#ifndef _ADDR_PACKET_H
#define _ADDR_PACKET_H

#include "packet.h"
#include "xvzd_types.h"

namespace xvzd {


class AddrPacket : public Packet {
public:
  AddrPacket(u_char *raw_packet, size_t size) : Packet(raw_packet, size) {};
  AddrPacket() {}

  vector<uint8_t> get_address(void);
  size_t  get_size(void);
};

}  // end of namespace


#endif  // _ADDR_PACKET_H
