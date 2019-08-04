#ifndef _ADDR_PACKET_H
#define _ADDR_PACKET_H

#include "packet.h"
#include "xvzd_types.h"

namespace xvzd {


class AddrPacket : public Packet {
public:
  AddrPacket(size_t _size, u_char *raw_packet) {
    size = _size;
    data = raw_packet;
  };
  AddrPacket() {}

  vector<uint8_t> get_address(void);
  size_t  get_size(void);
};

}  // end of namespace


#endif  // _ADDR_PACKET_H
