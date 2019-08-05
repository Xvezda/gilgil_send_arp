#ifndef _IP_ADDRESS_H
#define _IP_ADDRESS_H

#include "addr_packet.h"


namespace xvzd {

class IpAddress : public AddrPacket {
public:
  IpAddress(u_char *raw_packet, size_t size)
    : AddrPacket(raw_packet, size) {}
  IpAddress() {};
  ~IpAddress() {}

  vector<uint8_t> get_address(void);
};

}  // end of namespace


#endif  // _IP_ADDRESS_H

