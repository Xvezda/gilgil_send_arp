#ifndef _IP_ADDRESS_H
#define _IP_ADDRESS_H

#include "addr_packet.h"


namespace xvzd {

class IpAddress : public AddrPacket {
public:
  IpAddress(size_t size, u_char *raw_packet)
    : AddrPacket(size, raw_packet) {}
  IpAddress() {};
  ~IpAddress() {}
};

}  // end of namespace


#endif  // _IP_ADDRESS_H
