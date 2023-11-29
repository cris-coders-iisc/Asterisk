#include "sharing.h"

namespace asterisk {
//check the correctness of the following functions: 
template <>
void AuthAddShare<BoolRing>::randomize(emp::PRG& prg) {
 bool data[3];
 prg.random_bool(static_cast<bool*>(data), 3);
 key_sh_ = data[0];
 value_ = data[1];
 tag_ = data[2];
}

//the following functions have dependencies on the number of parties
//How to handle the following functions
/*
template <>
TPShare<BoolRing>::TPShare(BoolRing secret, emp::PRG& prg) {
  bool values[5];
  prg.random_bool(static_cast<bool*>(values), 5);

  BoolRing sum;
  for (size_t i = 0; i < 5; ++i) {
    share_elements[i] = values[i];
    sum += share_elements[i];
  }
  share_elements[5] = secret - sum;
}

template <>
void TPShare<BoolRing>::randomize(emp::PRG& prg) {
  bool values[6];
  prg.random_bool(static_cast<bool*>(values), 6);

  for (size_t i = 0; i < 6; ++i) {
    share_elements[i] = values[i];
  }
}*/
};  // namespace asterisk
