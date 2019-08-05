/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#include "ip_address.h"


using std::vector;
using xvzd::IpAddress;

vector<uint8_t> IpAddress::get_address() {
  vector<uint8_t> ret;
    char* token;
    char* address = new char[strlen(reinterpret_cast<char*>(data))];
    memcpy(address, data, strlen(reinterpret_cast<char*>(data)));

    // Tokenize to parse values
    token = strtok(address, ".");
    do {
      char *tmp;
#ifdef DEBUG
      printf("[DEBUG] %s:%d: %u\n",
          __FILE__, __LINE__,
          static_cast<uint8_t>(strtoul(token, &tmp, 10)));
#endif
      ret.push_back(static_cast<uint8_t>(strtoul(token, &tmp, 10)));
    } while ((token = strtok(NULL, ".")));

    delete[] address;

    return ret;
}

