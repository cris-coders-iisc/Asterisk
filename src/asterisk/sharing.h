#pragma once

#include <emp-tool/emp-tool.h>

#include <array>
#include <vector>

#include "../utils/helpers.h"
#include "../utils/types.h"

using namespace common::utils;

namespace asterisk {

template <class R>
class AuthAddShare {
  // key_sh is the additive share of the key used for the MAC
  // value_ will be additive share of my_id and tag_ will be the additive share of of the tag for my_id.
  R key_sh_;
  R value_;
  R tag_;
  
 public:
  AuthAddShare() = default;
  explicit AuthAddShare(R key_sh, R value, R tag)
      : key_sh_{key_sh}, value_{value}, tag_{tag} {}

  void randomize(emp::PRG& prg) {
    randomizeZZp(prg, key_sh_.data(), sizeof(R));
    randomizeZZp(prg, value_.data(), sizeof(R));
    randomizeZZp(prg, tag_.data(), sizeof(R));
  }

  R& valueAt() { return value_; }
  R& tagAt() { return tag_; }
  R& keySh() { return key_sh_; }

  void pushValue(R val) { value_ = val; } 
  void pushTag(R tag) {tag_ = tag; }
  void setKey(R key) {key_sh_ = key; }
  
  R valueAt() const { return value_; }
  R tagAt() const { return tag_; }
  R keySh() const { return key_sh_; }
  //Check this part
  //void randomize(emp::PRG& prg) {
  //  prg.random_data(values_.data(), sizeof(R) * 3); // This step is not clear 
  //}


  // Arithmetic operators.
  AuthAddShare<R>& operator+=(const AuthAddShare<R>& rhs) {
    value_ += rhs.value_;
    tag_ += rhs.tag_;
    key_sh_ = rhs.key_sh_;
    return *this;
  }

  // what is "friend"?
  friend AuthAddShare<R> operator+(AuthAddShare<R> lhs,
                                      const AuthAddShare<R>& rhs) {
    lhs += rhs;
    return lhs;
  }

  AuthAddShare<R>& operator-=(const AuthAddShare<R>& rhs) {
    (*this) += (rhs * R(-1));
    return *this;
  }

  friend AuthAddShare<R> operator-(AuthAddShare<R> lhs,
                                      const AuthAddShare<R>& rhs) {
    lhs -= rhs;
    return lhs;
  }

  AuthAddShare<R>& operator*=(const R& rhs) {
    value_ *= rhs;
    tag_ *= rhs;
    return *this;
  }

  friend AuthAddShare<R> operator*(AuthAddShare<R> lhs, const R& rhs) {
    lhs *= rhs;
    return lhs;
  }

  AuthAddShare<R>& operator<<=(const int& rhs) {
    uint64_t value = conv<uint64_t>(value_);
    uint64_t tag = conv<uint64_t>(tag_);
    value <<= rhs;
    tag <<= rhs;
    value_ = value;
    tag_ = tag;
    return *this;
  }

  friend AuthAddShare<R> operator<<(AuthAddShare<R> lhs, const int& rhs) {
    lhs <<= rhs;
    return lhs;
  }

  AuthAddShare<R>& operator>>=(const int& rhs) {
    uint64_t value = conv<uint64_t>(value_);
    uint64_t tag = conv<uint64_t>(tag_);
    value >>= rhs;
    tag >>= rhs;
    value_ = value;
    tag_ = tag;
    return *this;
  }

  friend AuthAddShare<R> operator>>(AuthAddShare<R> lhs, const int& rhs) {
    lhs >>= rhs;
    return lhs;
  }

  AuthAddShare<R>& add(R val, int pid) {
    if (pid == 1) {
      value_ += val;
      tag_ += key_sh_*val;
    } else {
      tag_ += key_sh_*val;
    }

    return *this;
  }

  AuthAddShare<R>& addWithAdder(R val, int pid, int adder) {
    if (pid == adder) {
      value_ += val;
      tag_ += key_sh_*val;
    } else {
      tag_ += key_sh_*val;
    }

    return *this;
  }

  AuthAddShare<R>& shift() {
    auto bits = bitDecomposeTwo(value_);
    if (bits[63] == 1)
      value_ = 1;
    else
      value_ = 0;
    bits = bitDecomposeTwo(tag_);
    if (bits[63] == 1)
      tag_ = 1;
    else
      tag_ = 0;

    return *this;
  }
  
};

template <class R>
class TPShare {
  R key_;
  std::vector<R> key_sh_;
  std::vector<R> values_;
  std::vector<R> tags_;

  public:
  TPShare() = default;
  explicit TPShare(R key, std::vector<R> key_sh, std::vector<R> value, std::vector<R> tag)
      : key_{key}, key_sh_{key_sh}, values_{std::move(value)}, tags_{std::move(tag)} {}

  // Access share elements.
  // idx = i retreives value common with party having i.
  R& operator[](size_t idx) { return values_.at(idx); }
  // idx = i retreives tag common with party having i.
  //R& operator()(size_t idx) { return tags_.at(idx); }
  
  R operator[](size_t idx) const { return values_.at(idx); }
  //R operator()(size_t idx) { return tags_.at(idx); }

  R& macKey() { return key_; }

  R& commonValueWithParty(int pid) {
    return values_.at(pid);
  }

  R& commonTagWithParty(int pid) {
    return tags_.at(pid);
  }

  R& commonKeyWithParty(int pid) {
    return key_sh_.at(pid);
  }

  [[nodiscard]] R commonValueWithParty(int pid) const {
    return values_.at(pid);
  }

  [[nodiscard]] R commonTagWithParty(int pid) const {
    return tags_.at(pid);
  }

  [[nodiscard]] R commonKeyWithParty(int pid) const {
    return key_sh_.at(pid);
  }

  void setKey( R key) {key_ = key;}
  void pushValues(R val) { values_.push_back(val); }
  void pushTags(R tag) {tags_.push_back(tag);}
  void setKeySh( R keysh) {key_sh_.push_back(keysh); }

  [[nodiscard]] R secret() const { 
    R res=values_[0];
    for (int i = 1; i < values_.size(); i++)
     res+=values_[i];
    return res;
  }
  // Arithmetic operators.
  TPShare<R>& operator+=(const TPShare<R>& rhs) {
    for (size_t i = 1; i < values_.size(); i++) {
      values_[i] += rhs.values_[i];
      tags_[i] += rhs.tags_[i];
        key_sh_[i] = rhs.key_sh_[i];
    }
    key_ = rhs.key_;
    return *this;
  }

  friend TPShare<R> operator+(TPShare<R> lhs,
                                      const TPShare<R>& rhs) {
    lhs += rhs;
    return lhs;
  }

  TPShare<R>& operator-=(const TPShare<R>& rhs) {
    (*this) += (rhs * R(-1));
    return *this;
  }

  friend TPShare<R> operator-(TPShare<R> lhs,
                                      const TPShare<R>& rhs) {
    lhs -= rhs;
    return lhs;
  }

  TPShare<R>& operator*=(const R& rhs) {
    for(size_t i = 1; i < values_.size(); i++) {
      values_[i] *= rhs;
      tags_[i] *= rhs;
    }
    return *this;
  }

  friend TPShare<R> operator*(TPShare<R> lhs, const R& rhs) {
    lhs *= rhs;
    return lhs;
  }

  TPShare<R>& operator<<=(const int& rhs) {
    for(size_t i = 1; i < values_.size(); i++) {
        uint64_t value = conv<uint64_t>(values_[i]);
        uint64_t tag = conv<uint64_t>(tags_[i]);
        value <<= rhs;
        tag <<= rhs;
        values_[i] = value;
        tags_[i] = tag;
    }
    return *this;
  }

  friend TPShare<R> operator<<(TPShare<R> lhs, const int& rhs) {
    lhs <<= rhs;
    return lhs;
  }

  TPShare<R>& operator>>=(const int& rhs) {
    for(size_t i = 1; i < values_.size(); i++) {
        uint64_t value = conv<uint64_t>(values_[i]);
        uint64_t tag = conv<uint64_t>(tags_[i]);
        value >>= rhs;
        tag >>= rhs;
        values_[i] = value;
        tags_[i] = tag;
    }
    return *this;
  }

  friend TPShare<R> operator>>(TPShare<R> lhs, const int& rhs) {
    lhs >>= rhs;
    return lhs;
  }

  AuthAddShare<R> getAAS(size_t pid){
    return AuthAddShare<R>({key_sh_.at(pid), values_.at(pid), tags_.at(pid)});
  }

  TPShare<R>& shift() {
    for(size_t i = 1; i < values_.size(); i++) {
      auto bits = bitDecomposeTwo(values_[i]);
      if(bits[63] == 1)
        values_[i] = 1;
      else 
        values_[i] = 0;

      bits = bitDecomposeTwo(tags_[i]);
      if(bits[63] == 1)
        tags_[i] = 1;
      else 
        tags_[i] = 0;
    }
    return *this;
  }

  //Add above
  
};

template <>
void AuthAddShare<BoolRing>::randomize(emp::PRG& prg);
//add the constructor above



// Contains all elements of a secret sharing. Used only for generating dummy
// preprocessing data.
/*
template <class R>
struct DummyShare { 
  // number of components will depent upon number of parties
  std::array<R, 6> share_elements;

  DummyShare() = default;

  explicit DummyShare(std::array<R, 6> share_elements)
      : share_elements(std::move(share_elements)) {}

  DummyShare(R secret, emp::PRG& prg) {
    prg.random_data(share_elements.data(), sizeof(R) * 5);

    R sum = share_elements[0];
    for (int i = 1; i < 5; ++i) {
      sum += share_elements[i];
    }
    share_elements[5] = secret - sum;
  }

  void randomize(emp::PRG& prg) {
    prg.random_data(share_elements.data(), sizeof(R) * 6);
  }

  [[nodiscard]] R secret() const {
    R sum = share_elements[0];
    for (size_t i = 1; i < 6; ++i) {
      sum += share_elements[i];
    }

    return sum;
  }

  DummyShare<R>& operator+=(const DummyShare<R>& rhs) {
    for (size_t i = 0; i < 6; ++i) {
      share_elements[i] += rhs.share_elements[i];
    }

    return *this;
  }

  friend DummyShare<R> operator+(DummyShare<R> lhs, const DummyShare<R>& rhs) {
    lhs += rhs;
    return lhs;
  }

  DummyShare<R>& operator-=(const DummyShare<R>& rhs) {
    for (size_t i = 0; i < 6; ++i) {
      share_elements[i] -= rhs.share_elements[i];
    }

    return *this;
  }

  friend DummyShare<R> operator-(DummyShare<R> lhs, const DummyShare<R>& rhs) {
    lhs -= rhs;
    return lhs;
  }

  DummyShare<R>& operator*=(const R& rhs) {
    for (size_t i = 0; i < 6; ++i) {
      share_elements[i] *= rhs;
    }

    return *this;
  }

  friend DummyShare<R> operator*(DummyShare<R> lhs, const R& rhs) {
    lhs *= rhs;
    return lhs;
  }

  friend DummyShare<R> operator*(const R& lhs, DummyShare<R> rhs) {
    // Assumes abelian ring.
    rhs *= lhs;
    return rhs;
  }

  //ReplicatedShare<R> getRSS(size_t pid) {
  //  return ReplicatedShare<R>({getShareElement(pid, pidFromOffset(pid, 1)),
  //                             getShareElement(pid, pidFromOffset(pid, 2)),
  //                             getShareElement(pid, pidFromOffset(pid, 3))});
  //}

  R getShareElement(size_t i, size_t j) {
    return share_elements.at(upperTriangularToArray(i, j));
  }
};*/

//template <>
//void AuthAddShare<BoolRing>::randomize(emp::PRG& prg);

//template <>
//TPShare<BoolRing>::TPShare(BoolRing secret, emp::PRG& prg);

//template <>
//void TPShare<BoolRing>::randomize(emp::PRG& prg);
};  // namespace asterisk
