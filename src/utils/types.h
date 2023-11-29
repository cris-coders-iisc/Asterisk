#pragma once
#include <emp-tool/emp-tool.h>

#include <NTL/ZZ_p.h>

#include <cstdint>
#include <iostream>
#include <vector>

using namespace NTL;

namespace common::utils {
using Ring = uint64_t;
// constexpr uint64_t FRACTION = 16;

// using Field = NTL::ZZ_p;
constexpr uint64_t FIELDSIZE = 8; // bytes
// using Field = uint64_t;
constexpr uint64_t FRACTION = 16;
// using Field = int;

using Field = ZZ_p; 

class BoolRing {
  bool val_;

 public:
  BoolRing();
  BoolRing(bool val);
  BoolRing(int val);

  [[nodiscard]] bool val() const;

  bool operator==(const BoolRing& rhs) const;

  BoolRing& operator+=(const BoolRing& rhs);
  BoolRing& operator-=(const BoolRing& rhs);
  BoolRing& operator*=(const BoolRing& rhs);
  BoolRing& operator=(const BoolRing& rhs) noexcept;

  static std::vector<uint8_t> pack(const BoolRing* data, size_t len);
  static std::vector<BoolRing> unpack(const uint8_t* packed, size_t len);

  friend BoolRing operator+(BoolRing lhs, const BoolRing& rhs);
  friend BoolRing operator-(BoolRing lhs, const BoolRing& rhs);
  friend BoolRing operator*(BoolRing lhs, const BoolRing& rhs);

  friend std::ostream& operator<<(std::ostream& os, const BoolRing& b);
};
};  // namespace common::utils 
