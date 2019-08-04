#ifndef _ETH_PACKET_H
#define _ETH_PACKET_H

#include "packet.h"
#include "xvzd_types.h"


namespace xvzd {

enum EthType : uint16_t {
  TYPE_UNKNOWN = 0x0000,
  TYPE_IPV4    = 0x0800,
  TYPE_ARP     = 0x0806
};

class EthPacket : public Packet {
public:
  EthPacket(u_char *raw_packet) {
    assert(raw_packet != nullptr);

    u_char* cursor = raw_packet;

    read_cursor(cursor, dmac, 6);
    read_cursor(cursor, smac, 6);

    read_cursor(cursor, type, 2);

    // Put all remaining datas
    data = cursor;
  }
  ~EthPacket() {}

  vector<uint8_t> get_dmac(void);
  vector<uint8_t> get_smac(void);
  EthType         get_type(void);
  Packet*         get_data(void);
private:
  u_char*         dmac;
  u_char*         smac;
  u_char*         type;
  u_char*         data;
  u_char*         crc;
};

}  // end of namespace


#endif  // _ETH_PACKET_H

