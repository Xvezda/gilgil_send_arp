#ifndef _ARP_PACKET_H
#define _ARP_PACKET_H


#include "packet.h"
#include "xvzd_types.h"


namespace xvzd {

const size_t HARDWARE_TYPE_SIZE = 2;
const size_t PROTOCOL_TYPE_SIZE = 2;
const size_t HARDWARE_ADDR_LEN = 1;
const size_t PROTOCOL_ADDR_LEN = 1;
const size_t OPERATION_CODE_SIZE = 2;

enum ArpOpCode : uint16_t {
  ARP_UNKNOWN = 0x0000,
  ARP_REQUEST = 0x0001,
  ARP_REPLY   = 0x0002
};

class ArpPacket : public Packet {
public:
  ArpPacket() {}
  ArpPacket(u_char *raw_packet) {
    assert(raw_packet != nullptr);

    u_char *cursor = raw_packet;

    read_cursor(cursor, hardware_type, 2);
    read_cursor(cursor, protocol_type, 2);
    read_cursor(cursor, hardware_size, 1);
    read_cursor(cursor, protocol_size, 1);

    read_cursor(cursor, operation, 2);

    read_cursor(cursor, sender_address, get_hardware_size());
    read_cursor(cursor, sender_ip, get_protocol_size());
    read_cursor(cursor, target_address, get_hardware_size());
    read_cursor(cursor, target_ip, get_protocol_size());
  }
  ~ArpPacket() {}

  uint16_t        get_hardware_type(void);
  uint16_t        get_protocol_type(void);
  uint8_t         get_hardware_size(void);
  uint8_t         get_protocol_size(void);
  ArpOpCode       get_operation(void);
  vector<uint8_t> get_sender_address(void);
  vector<uint8_t> get_sender_ip(void);
  vector<uint8_t> get_target_address(void);
  vector<uint8_t> get_target_ip(void);

  size_t          get_size(void);
  u_char*         to_rawstring(void);

private:
  u_char*         hardware_type;
  u_char*         protocol_type;
  u_char*         hardware_size;
  u_char*         protocol_size;
  u_char*         operation;
  u_char*         sender_address;
  u_char*         sender_ip;
  u_char*         target_address;
  u_char*         target_ip;

  size_t get_fixed_header_length() {
    return (HARDWARE_TYPE_SIZE + PROTOCOL_TYPE_SIZE + HARDWARE_ADDR_LEN
        + PROTOCOL_ADDR_LEN + OPERATION_CODE_SIZE);
  }
};

}  // end of namespace


#endif  // _ARP_PACKET_H

