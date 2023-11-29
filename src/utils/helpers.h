#pragma once

#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pE.h>
#include <emp-tool/emp-tool.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "../io/netmp.h"
#include "types.h"

namespace common::utils  {
int pidFromOffset(int id, int offset);
int offsetFromPid(int id, int pid);
size_t upperTriangularToArray(size_t i, size_t j);

// Supports only native int type.
template <class R>
std::vector<BoolRing> bitDecompose(R val) {
  auto num_bits = sizeof(val) * 8;
  std::vector<BoolRing> res(num_bits);
  for (size_t i = 0; i < num_bits; ++i) {
    res[i] = ((val >> i) & 1ULL) == 1;
  }

  return res;
}

template <class R>
std::vector<BoolRing> bitDecomposeTwo(R value) {
  uint64_t val = conv<uint64_t>(value);
  return bitDecompose(val);
}


std::vector<uint64_t> packBool(const bool* data, size_t len);
void unpackBool(const std::vector<uint64_t>& packed, bool* data, size_t len);
void randomizeZZp(emp::PRG& prg, NTL::ZZ_p& val, int nbytes);
void randomizeZZpE(emp::PRG& prg, NTL::ZZ_pE& val);
void randomizeZZpE(emp::PRG& prg, NTL::ZZ_pE& val, Ring rval);

void sendZZpE(emp::NetIO* ios, const NTL::ZZ_pE* data, size_t length);
void receiveZZpE(emp::NetIO* ios, NTL::ZZ_pE* data, size_t length);
};  // namespace common::utils 
