// MIT License
//
// Copyright (c) 2018 Xiao Wang (wangxiao@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// The following code has been adopted from
// https://github.com/emp-toolkit/emp-agmpc. It has been modified to define the
// class within a namespace and add additional methods (sendRelative,
// recvRelative).

#pragma once

#include <emp-tool/emp-tool.h>
#include "../utils/types.h"
#include <vector>

namespace io {
using namespace emp;
using namespace common::utils;

class NetIOMP {
 public:
  std::vector<std::unique_ptr<NetIO>> ios;
  std::vector<std::unique_ptr<NetIO>> ios2;
  int party;
  int nP;
  std::vector<bool> sent;

  NetIOMP(int party, int nP, int port, char* IP[], bool localhost = false)
      : ios(nP), ios2(nP), party(party), nP(nP), sent(nP, false) {
    for (int i = 0; i < nP; ++i) {
      for (int j = i + 1; j < nP; ++j) {
        if (i == party) {
          usleep(1000);
          if (localhost) {
            ios[j] = std::make_unique<NetIO>("127.0.0.1", port + 2 * (i * nP + j), true);
          } else {
            ios[j] = std::make_unique<NetIO>(IP[j], port + 2 * (i * nP +j), true);
          }
          ios[j]->set_nodelay();

          usleep(1000);
          if (localhost) {
            ios2[j] = std::make_unique<NetIO>(nullptr, port + 2 * (i * nP + j) + 1, true);
          } else {
            ios2[j] = std::make_unique<NetIO>(nullptr, port + 2 * (i * nP +j) + 1, true);
          }
          ios2[j]->set_nodelay();
        } else if (j == party) {
          usleep(1000);
          if (localhost) {
            ios[i] = std::make_unique<NetIO>(nullptr, port + 2 * (i * nP + j), true);
          } else {
            ios[i] = std::make_unique<NetIO>(nullptr, port + 2 * (i * nP +j), true);
          }
          ios[i]->set_nodelay();

          usleep(1000);
          if (localhost) {
            ios2[i] = std::make_unique<NetIO>("127.0.0.1", port + 2 * (i * nP + j) + 1, true);
          } else {
            ios2[i] = std::make_unique<NetIO>(IP[i], port + 2 * (i * nP +j) + 1, true);
          }
          ios2[i]->set_nodelay();
        }
      }
    }
  }

  int64_t count() {
    int64_t res = 0;
    for (int i = 0; i < nP; ++i)
      if (i != party) {
        res += ios[i]->counter;
        res += ios2[i]->counter;
      }
    return res;
  }

  void resetStats() {
    for (int i = 0; i < nP; ++i) {
      if (i != party) {
        ios[i]->counter = 0;
        ios2[i]->counter = 0;
      }
    }
  }

  void send(int dst, const void* data, size_t len) {
    if (dst != -1 and dst != party) {
      if (party < dst)
        ios[dst]->send_data(data, len);
      else
        ios2[dst]->send_data(data, len);
      sent[dst] = true;
    }
    #ifdef __clang__
        flush(dst);
    #endif
  }

  void send(int dst, const NTL::ZZ_p* data, size_t length) {
  
  // Assumes that every co-efficient of ZZ_pE is same range as Ring.
  std::vector<uint8_t> serialized(length);
  size_t num = (length + FIELDSIZE - 1) / FIELDSIZE;
  for (size_t i = 0; i < num; ++i) {
    NTL::BytesFromZZ(serialized.data() + i * FIELDSIZE, NTL::conv<NTL::ZZ>(data[i]), FIELDSIZE);
  }
  send(dst, serialized.data(), serialized.size());
}

  void sendRelative(int offset, const void* data, size_t len) {
    int dst = (party + offset) % nP;
    if (dst < 0) {
      dst += nP;
    }
    send(dst, data, len);
  }

  void sendBool(int dst, const bool* data, size_t len) {
    for (int i = 0; i < len;) {
      uint64_t tmp = 0;
      for (int j = 0; j < 64 && i < len; ++i, ++j) {
        if (data[i]) {
          tmp |= (0x1ULL << j);
        }
      }
      send(dst, &tmp, 8);
    }
  }

  void sendBoolRelative(int offset, const bool* data, size_t len) {
    int dst = (party + offset) % nP;
    if (dst < 0) {
      dst += nP;
    }
    sendBool(dst, data, len);
  }

  void recv(int src, void* data, size_t len) {
    if (src != -1 && src != party) {
      if (sent[src]) flush(src);
      if (src < party)
        ios[src]->recv_data(data, len);
      else
        ios2[src]->recv_data(data, len);
    }
  }

  void recv(int dst, NTL::ZZ_p* data, size_t length) {
    std::vector<uint8_t> serialized(length);
    recv(dst, serialized.data(), serialized.size());
    // Assumes that every co-efficient of ZZ_pE is same range as Ring.
    
    size_t num = (length + FIELDSIZE - 1) / FIELDSIZE;
    for (size_t i = 0; i < num; ++i) {
      data[i] = NTL::conv<NTL::ZZ_p>(NTL::ZZFromBytes(serialized.data() + i * FIELDSIZE, FIELDSIZE));
    }
  }

  void recvRelative(int offset, void* data, size_t len) {
    int src = (party + offset) % nP;
    if (src < 0) {
      src += nP;
    }
    recv(src, data, len);
  }

  void recvBool(int src, bool* data, size_t len) {
    for (int i = 0; i < len;) {
      uint64_t tmp = 0;
      recv(src, &tmp, 8);
      for (int j = 63; j >= 0 && i < len; ++i, --j) {
        data[i] = (tmp & 0x1) == 0x1;
        tmp >>= 1;
      }
    }
  }

  void recvRelative(int offset, bool* data, size_t len) {
    int src = (party + offset) % nP;
    if (src < 0) {
      src += nP;
    }
    recvBool(src, data, len);
  }

  NetIO* get(size_t idx, bool b = false) {
    if (b)
      return ios[idx].get();
    else
      return ios2[idx].get();
  }

  NetIO* getSendChannel(size_t idx) {
    if (party < idx) {
      return ios[idx].get();
    }

    return ios2[idx].get();
  }

  NetIO* getRecvChannel(size_t idx) {
    if (idx < party) {
      return ios[idx].get();
    }

    return ios2[idx].get();
  }

  void flush(int idx = -1) {
    if (idx == -1) {
      for (int i = 0; i < nP; ++i) {
        if (i != party) {
          ios[i]->flush();
          ios2[i]->flush();
        }
      }
    } else {
      if (party < idx) {
        ios[idx]->flush();
      } else {
        ios2[idx]->flush();
      }
    }
  }

  void sync() {
    for (int i = 0; i < nP; ++i) {
      for (int j = 0; j < nP; ++j) {
        if (i < j) {
          if (i == party) {
            ios[j]->sync();
            ios2[j]->sync();
          } else if (j == party) {
            ios[i]->sync();
            ios2[i]->sync();
          }
        }
      }
    }
  }
};
};  // namespace io
