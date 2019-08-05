#ifndef _MAC_ADDRESS_H
#define _MAC_ADDRESS_H


#include "addr_packet.h"


namespace xvzd {


class MacAddress : public AddrPacket {
public:
  MacAddress(u_char *raw_packet, size_t size)
    : AddrPacket(raw_packet, size) {}
  MacAddress() {};
  ~MacAddress() {}
};

}  // end of namespace


#endif  // _MAC_ADDRESS_H

