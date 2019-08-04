#ifndef _PACKET_H
#define _PACKET_H

#include <arpa/inet.h>
#include "xvzd_types.h"

namespace xvzd {

inline void read_cursor(u_char*& cursor, u_char*& target, size_t size) {
  target = cursor;
  cursor += size;
}

inline uint16_t get_uint32_t(u_char *raw_packet) {
  return ntohl(reinterpret_cast<uint32_t&>(*raw_packet));
}

inline uint16_t get_uint16_t(u_char *raw_packet) {
  return ntohs(reinterpret_cast<uint16_t&>(*raw_packet));
}

// Base class
class Packet {
public:
  Packet() {}
  Packet(u_char *raw_packet) : data(raw_packet) {}
  ~Packet() {}

  size_t get_size(void);
protected:
  size_t  size;
  u_char* data;
};

}  // end of namespace


#endif  // _PACKET_H

