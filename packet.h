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
  Packet(u_char *raw_packet, size_t _size) : data(raw_packet), size(_size) {}
  ~Packet() {}

  size_t get_size(void);
  size_t to_rawstr(void);
protected:
  u_char* data;
  size_t  size;
};

}  // end of namespace


#endif  // _PACKET_H

