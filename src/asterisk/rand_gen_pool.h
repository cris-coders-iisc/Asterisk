#pragma once
#include <emp-tool/emp-tool.h>

#include <vector>
#include <algorithm>
#include "../utils/helpers.h"

// #include "../utils/helpers.h"

using namespace common::utils;

namespace asterisk {

// Collection of PRGs.
class RandGenPool {
  int id_;

  emp::PRG k_p0;
  emp::PRG k_self;
  emp::PRG k_all_minus_0;
  emp::PRG k_all;
  std::vector<emp::PRG> k_pi;
  

 public:
  explicit RandGenPool(int my_id, int num_parties, uint64_t seed = 200);
  
  emp::PRG& self();// { return k_self; }
  emp::PRG& all_minus_0();//{ return k_all_minus_0; }
  emp::PRG& all();//{ return k_all; }
  emp::PRG& p0();// { return k_p0; }
  emp::PRG& pi( int i);
};

};  // namespace asterisk
