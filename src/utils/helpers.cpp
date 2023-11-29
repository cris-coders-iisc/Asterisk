#include "helpers.h"

#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>

#include <cmath>

namespace common::utils {
int pidFromOffset(int id, int offset) {
  int pid = (id + offset) % 4;
  if (pid < 0) {
    pid += 4;
  }
  return pid;
}

int offsetFromPid(int id, int pid) {
  if (id < pid) {
    return pid - id;
  }

  return 4 + pid - id;
}

size_t upperTriangularToArray(size_t i, size_t j) {
  // (i, j) co-ordinate in upper triangular matrix (without diagonal) to array
  // index in column major order.
  auto mn = std::min(i, j);
  auto mx = std::max(i, j);
  auto idx = (mx * (mx - 1)) / 2 + mn;
  return idx;
}

std::vector<uint64_t> packBool(const bool* data, size_t len) {
  std::vector<uint64_t> res;
  for (size_t i = 0; i < len;) {
    uint64_t temp = 0;
    for (size_t j = 0; j < 64 && i < len; ++j, ++i) {
      if (data[i]) {
        temp |= (0x1ULL << j);
      }
    }
    res.push_back(temp);
  }

  return res;
}

void unpackBool(const std::vector<uint64_t>& packed, bool* data, size_t len) {
  for (size_t i = 0, count = 0; i < len; count++) {
    uint64_t temp = packed[count];
    for (int j = 63; j >= 0 && i < len; ++i, --j) {
      data[i] = (temp & 0x1) == 0x1;
      temp >>= 1;
    }
  }
}

void randomizeZZp(emp::PRG& prg, NTL::ZZ_p& val, int nbytes) {
    uint64_t var;
    prg.random_data(&var, nbytes);
    val = NTL::ZZ_p(var);
}

void randomizeZZpE(emp::PRG& prg, NTL::ZZ_pE& val) {
  std::vector<Ring> coeff(NTL::ZZ_pE::degree());
  prg.random_data(coeff.data(), sizeof(Ring) * coeff.size());

  NTL::ZZ_pX temp;
  temp.SetLength(NTL::ZZ_pE::degree());

  for (size_t i = 0; i < coeff.size(); ++i) {
    temp[i] = coeff[i];
  }

  NTL::conv(val, temp);
}

void randomizeZZpE(emp::PRG& prg, NTL::ZZ_pE& val, Ring rval) {
  std::vector<Ring> coeff(NTL::ZZ_pE::degree() - 1);
  prg.random_data(coeff.data(), sizeof(Ring) * coeff.size());

  NTL::ZZ_pX temp;
  temp.SetLength(NTL::ZZ_pE::degree());

  temp[0] = rval;
  for (size_t i = 1; i < coeff.size(); ++i) {
    temp[i] = coeff[i];
  }

  NTL::conv(val, temp);
}

void receiveZZpE(emp::NetIO* ios, NTL::ZZ_pE* data, size_t length) {
  auto degree = NTL::ZZ_pE::degree();
  // Assumes that every co-efficient of ZZ_pE is same range as Ring.
  std::vector<uint8_t> serialized(sizeof(Ring));

  NTL::ZZ_pX poly;
  poly.SetLength(degree);
  for (size_t i = 0; i < length; ++i) {
    for (size_t d = 0; d < degree; ++d) {
      ios->recv_data(serialized.data(), serialized.size());
      auto coeff = NTL::conv<NTL::ZZ_p>(
          NTL::ZZFromBytes(serialized.data(), serialized.size()));
      poly[d] = coeff;
    }
    NTL::conv(data[i], poly);
  }
}

void sendZZpE(emp::NetIO* ios, const NTL::ZZ_pE* data, size_t length) {
  auto degree = NTL::ZZ_pE::degree();
  // Assumes that every co-efficient of ZZ_pE is same range as Ring.
  std::vector<uint8_t> serialized(sizeof(Ring));

  for (size_t i = 0; i < length; ++i) {
    const auto& poly = NTL::rep(data[i]);
    for (size_t d = 0; d < degree; ++d) {
      const auto& coeff = NTL::rep(NTL::coeff(poly, d));
      NTL::BytesFromZZ(serialized.data(), coeff, serialized.size());
      ios->send_data(serialized.data(), serialized.size());
    }
  }
  ios->flush();
}
};  // namespace common::utils 
