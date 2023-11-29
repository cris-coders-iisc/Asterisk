#include "types.h"

namespace common::utils {
BoolRing::BoolRing() : val_(false) {}

BoolRing::BoolRing(bool val) : val_(val) {}

BoolRing::BoolRing(int val) : val_(val != 0) {}

bool BoolRing::val() const { return val_; }

bool BoolRing::operator==(const BoolRing& rhs) const {
  return val_ == rhs.val_;
}

BoolRing& BoolRing::operator+=(const BoolRing& rhs) {
  val_ = val_ ^ rhs.val_;
  return *this;
}

BoolRing& BoolRing::operator-=(const BoolRing& rhs) {
  (*this) += rhs;
  return *this;
}

BoolRing& BoolRing::operator*=(const BoolRing& rhs) {
  val_ = val_ && rhs.val_;
  return *this;
}

BoolRing& BoolRing::operator=(const BoolRing& rhs) noexcept{
  if(rhs.val_ == 0) {
    val_ = rhs.val_;
  }
  else {
    val_ = 1;
  }
  
  return *this;
}

std::vector<uint8_t> BoolRing::pack(const BoolRing* data, size_t len) {
  std::vector<uint8_t> res;
  for (size_t i = 0; i < len;) {
    uint8_t temp = 0;
    for (size_t j = 0; j < 8 && i < len; ++j, ++i) {
      if (data[i].val()) {
        temp |= (1U << j);
      }
    }
    res.push_back(temp);
  }

  return res;
}

std::vector<BoolRing> BoolRing::unpack(const uint8_t* packed, size_t len) {
  std::vector<BoolRing> res(len);
  for (size_t i = 0, count = 0; i < len; count++) {
    uint8_t temp = packed[count];
    for (int j = 7; j >= 0 && i < len; ++i, --j) {
      res[i] = (temp & 1U) == 1;
      temp >>= 1U;
    }
  }

  return res;
}

BoolRing operator+(BoolRing lhs, const BoolRing& rhs) {
  lhs += rhs;
  return lhs;
}

BoolRing operator-(BoolRing lhs, const BoolRing& rhs) {
  lhs -= rhs;
  return lhs;
}

BoolRing operator*(BoolRing lhs, const BoolRing& rhs) {
  lhs *= rhs;
  return lhs;
}

std::ostream& operator<<(std::ostream& os, const BoolRing& b) {
  os << b.val_;
  return os;
}
};  // namespace common::utils
