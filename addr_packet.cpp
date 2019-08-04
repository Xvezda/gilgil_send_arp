/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "send_arp.h"


using std::vector;
using xvzd::AddrPacket;


vector<uint8_t> AddrPacket::get_address() {
  vector<uint8_t> ret;
    uint8_t i = 0;
    char *token;
    u_char* address = data;

    // Tokenize to parse values
    token = strtok(reinterpret_cast<char*>(address), ".");
    do {
      char *tmp;
      ret.push_back(strtoul(token, &tmp, 10));
      ++i;
    } while ((token = strtok(NULL, ".")));

    return ret;
}
