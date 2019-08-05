/*
 * Copyright (C) 2019 Xvezda <https://xvezda.com/>
 */
#ifndef _XVZD_STRING_H
#define _XVZD_STRING_H


#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <stdint.h>


namespace xvzd {


using std::vector;

using std::snprintf;
using std::strlen;
using std::memcpy;

class BaseObject {
public:
  BaseObject() {}
  ~BaseObject() {}
  virtual char* to_cstr() = 0;
};

class String : public BaseObject {
public:
  String() {}
  String(char* src) {
    size = strlen(src);
    data = new char[size+1];

    memcpy(data, src, size);

    data[size] = '\0';
  }

  String(vector<uint8_t> arr) {
    char *tmp = nullptr;

    size_t len = 0;
    size_t i, offset;

    for (i = 0; i < arr.size(); ++i) {
      // Get result length
      len += snprintf(0, 0,
          "%02x%c", arr[i], (i == arr.size()-1) ? '\0' : ' ');
    }
    tmp = new char[len+1];
    for (i = 0, offset = 0; i < arr.size(); ++i) {
      offset += snprintf(tmp+offset, len-offset,
          "%02x%c", arr[i], (i == arr.size()-1) ? '\0' : ' ');
    }
    tmp[len] = '\0';

    data = tmp;
    size = len;
  }

  ~String() {
    if (data != nullptr) {
      delete[] data;
      data = nullptr;
    }
  }

  char* to_cstr() {
    return data;
  }
protected:
  size_t size;
private:
  char  *data;
};

}  // end of namespace


#endif  // _XVZD_STRING_H

