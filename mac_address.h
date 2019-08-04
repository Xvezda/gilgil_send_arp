#ifndef _MAC_ADDRESS_H
#define _MAC_ADDRESS_H


#include "addr_packet.h"


namespace xvzd {


class MacAddress : public AddrPacket {
public:
  MacAddress(size_t size, u_char *raw_packet)
    : AddrPacket(size, raw_packet) {}
  MacAddress() {};
  ~MacAddress() {}
};

}  // end of namespace


#endif  // _MAC_ADDRESS_H

