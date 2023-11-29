#pragma once

#include "../utils/circuit.h"
#include "sharing.h"
#include "../utils/types.h"

using namespace common::utils;

namespace assistedMPC {
// Preprocessed data for a gate.
template <class R>
struct PreprocGate {
  // Secret shared mask for the output wire of the gate.
  AuthAddShare<R> mask{};
  TPShare<R> tpmask{};

  PreprocGate() = default;

  explicit PreprocGate(const AuthAddShare<R>& mask, const TPShare<R>& tpmask) 
      : mask(mask), tpmask(tpmask) {}

  virtual ~PreprocGate() = default;
};

template <class R>
using preprocg_ptr_t = std::unique_ptr<PreprocGate<R>>;

template <class R>
struct PreprocInput : public PreprocGate<R> {
  // ID of party providing input on wire.
  int pid{};
  // Plaintext value of mask on input wire. Non-zero for all parties except
  // party with id 'pid'.
  R mask_value{};

  PreprocInput() = default;
  PreprocInput(const AuthAddShare<R>& mask, const TPShare<R>& tpmask, int pid, R mask_value = 0) 
      : PreprocGate<R>(mask, tpmask), pid(pid), mask_value(mask_value) {}
};

template <class R>
struct PreprocMultGate : public PreprocGate<R> {
  // Secret shared product of inputs masks.
  AuthAddShare<R> mask_prod{};
  TPShare<R> tpmask_prod{};

  PreprocMultGate() = default;
  PreprocMultGate(const AuthAddShare<R>& mask, const TPShare<R>& tpmask,
                  const AuthAddShare<R>& mask_prod, const TPShare<R>& tpmask_prod)
      : PreprocGate<R>(mask, tpmask), mask_prod(mask_prod), tpmask_prod(tpmask_prod) {}
};

template <class R>
struct PreprocMult3Gate : public PreprocGate<R> {
  // Secret shared product of inputs masks.
  AuthAddShare<R> mask_ab{};
  TPShare<R> tpmask_ab{};

  AuthAddShare<R> mask_ac{};
  TPShare<R> tpmask_ac{};

  AuthAddShare<R> mask_bc{};
  TPShare<R> tpmask_bc{};

  AuthAddShare<R> mask_abc{};
  TPShare<R> tpmask_abc{};

  PreprocMult3Gate() = default;
  PreprocMult3Gate(const AuthAddShare<R>& mask, const TPShare<R>& tpmask,
                  const AuthAddShare<R>& mask_ab, const TPShare<R>& tpmask_ab,
                  const AuthAddShare<R>& mask_ac, const TPShare<R>& tpmask_ac,
                  const AuthAddShare<R>& mask_bc, const TPShare<R>& tpmask_bc,
                  const AuthAddShare<R>& mask_abc, const TPShare<R>& tpmask_abc)
      : PreprocGate<R>(mask, tpmask), mask_ab(mask_ab), tpmask_ab(tpmask_ab),
                                      mask_ac(mask_ac), tpmask_ac(tpmask_ac),
                                      mask_bc(mask_bc), tpmask_bc(tpmask_bc),
                                      mask_abc(mask_abc), tpmask_abc(tpmask_abc){}
};


template <class R>
struct PreprocMult4Gate : public PreprocGate<R> {
  // Secret shared product of inputs masks.
  AuthAddShare<R> mask_abcd{};
  TPShare<R> tpmask_abcd{};

  AuthAddShare<R> mask_abc{};
  TPShare<R> tpmask_abc{};

  AuthAddShare<R> mask_abd{};
  TPShare<R> tpmask_abd{};

  AuthAddShare<R> mask_acd{};
  TPShare<R> tpmask_acd{};

  AuthAddShare<R> mask_bcd{};
  TPShare<R> tpmask_bcd{};

  AuthAddShare<R> mask_ab{};
  TPShare<R> tpmask_ab{};

  AuthAddShare<R> mask_ac{};
  TPShare<R> tpmask_ac{};

  AuthAddShare<R> mask_ad{};
  TPShare<R> tpmask_ad{};

  AuthAddShare<R> mask_bc{};
  TPShare<R> tpmask_bc{};

  AuthAddShare<R> mask_bd{};
  TPShare<R> tpmask_bd{};

  AuthAddShare<R> mask_cd{};
  TPShare<R> tpmask_cd{};


  PreprocMult4Gate() = default;
  PreprocMult4Gate(const AuthAddShare<R>& mask, const TPShare<R>& tpmask,
                  const AuthAddShare<R>& mask_ab, const TPShare<R>& tpmask_ab,
                  const AuthAddShare<R>& mask_ac, const TPShare<R>& tpmask_ac,
                  const AuthAddShare<R>& mask_ad, const TPShare<R>& tpmask_ad,
                  const AuthAddShare<R>& mask_bc, const TPShare<R>& tpmask_bc,
                  const AuthAddShare<R>& mask_bd, const TPShare<R>& tpmask_bd,
                  const AuthAddShare<R>& mask_cd, const TPShare<R>& tpmask_cd,
                  const AuthAddShare<R>& mask_abc, const TPShare<R>& tpmask_abc,
                  const AuthAddShare<R>& mask_abd, const TPShare<R>& tpmask_abd,
                  const AuthAddShare<R>& mask_acd, const TPShare<R>& tpmask_acd,
                  const AuthAddShare<R>& mask_bcd, const TPShare<R>& tpmask_bcd,
                  const AuthAddShare<R>& mask_abcd, const TPShare<R>& tpmask_abcd)
      : PreprocGate<R>(mask, tpmask), mask_ab(mask_ab), tpmask_ab(tpmask_ab),
                                      mask_ac(mask_ac), tpmask_ac(tpmask_ac),
                                      mask_ad(mask_ad), tpmask_ad(tpmask_ad),
                                      mask_bc(mask_bc), tpmask_bc(tpmask_bc),
                                      mask_bd(mask_bd), tpmask_bd(tpmask_bd),
                                      mask_cd(mask_cd), tpmask_cd(tpmask_cd), 
                                      mask_abc(mask_abc), tpmask_abc(tpmask_abc),
                                      mask_abd(mask_abd), tpmask_abd(tpmask_abd),
                                      mask_acd(mask_acd), tpmask_acd(tpmask_acd),
                                      mask_bcd(mask_bcd), tpmask_bcd(tpmask_bcd),
                                      mask_abcd(mask_abcd), tpmask_abcd(tpmask_abcd) {}
};

template <class R>
struct PreprocDotpGate : public PreprocGate<R> {
  AuthAddShare<R> mask_prod{};
  TPShare<R> tpmask_prod{};

  PreprocDotpGate() = default;
  PreprocDotpGate(const AuthAddShare<R>& mask, const TPShare<R>& tpmask,
                  const AuthAddShare<R>& mask_prod, const TPShare<R>& tpmask_prod)
      : PreprocGate<R>(mask, tpmask), mask_prod(mask_prod), tpmask_prod(tpmask_prod) {}
};


template <class R>
struct PreprocEqzGate : public PreprocGate<R> {
  AuthAddShare<R> mask_b;
  TPShare<R> tpmask_b;

  AuthAddShare<R> mask_w;
  TPShare<R> tpmask_w;

  AuthAddShare<R> rval;
  TPShare<R> tprval;

  std::vector<preprocg_ptr_t<BoolRing>> multk_gates;

  R padded_val;

  PreprocEqzGate() = default;
  PreprocEqzGate(AuthAddShare<R> mask_w, TPShare<R> tpmask_w, 
                  AuthAddShare<R> mask_b, TPShare<R> tpmask_b,
                  AuthAddShare<R> rval, TPShare<R> tprval,
                  std::vector<preprocg_ptr_t<BoolRing>> multk_gates,
                  R padded_val)
    : PreprocGate<R>((mask_b * ( -1 ) + mask_w * ( -2 ) ), (tpmask_b * ( -1 ) + tpmask_w * ( -2 ))),
      mask_w(mask_w), tpmask_w(tpmask_w),
      mask_b(mask_b), tpmask_b(tpmask_b),
      rval(rval), tprval(tprval),
      multk_gates(std::move(multk_gates)),
      padded_val(padded_val) {}
};

template <class R>
struct PreprocLtzGate : public PreprocGate<R> {
  R padded_val;
  
  AuthAddShare<R> r_val;
  TPShare<R> tpr_val;

  AuthAddShare<R> mask_b;
  TPShare<R> tpmask_b;

  AuthAddShare<R> mask_w;
  TPShare<R> tpmask_w;

  AuthAddShare<R> mask_v;
  TPShare<R> tpmask_v;

  AuthAddShare<R> mask_out;
  TPShare<R> tpmask_out;

  std::vector<preprocg_ptr_t<BoolRing>> PrefixAND_gates;

  PreprocLtzGate() = default;
  PreprocLtzGate(AuthAddShare<R> mask_out, TPShare<R> tpmask_out,
                 AuthAddShare<R> mask_v, TPShare<R> tpmask_v,
                 AuthAddShare<R> mask_w, TPShare<R> tpmask_w,
                 AuthAddShare<R> mask_b, TPShare<R> tpmask_b,
                 AuthAddShare<R> r_val, TPShare<R> tpr_val,
                 std::vector<preprocg_ptr_t<BoolRing>> PrefixAND_gates, R padded_val)
    : PreprocGate<R>((mask_out), (tpmask_out)),
      mask_v(mask_v), tpmask_v(tpmask_v),
      mask_w(mask_w), tpmask_w(tpmask_w),
      mask_b(mask_b), tpmask_b(tpmask_b),
      r_val(r_val), tpr_val(tpr_val),
      PrefixAND_gates(std::move(PrefixAND_gates)),
      padded_val(padded_val) {}
};
/*template <class R>
struct PreprocTrDotpGate : public PreprocGate<R> {
  ReplicatedShare<Ring> mask_prod{};
  ReplicatedShare<Ring> mask_d{};

  PreprocTrDotpGate() = default;
  PreprocTrDotpGate(const ReplicatedShare<Ring>& mask,
                    const ReplicatedShare<Ring>& mask_prod,
                    const ReplicatedShare<Ring>& mask_d)
      : PreprocGate<R>(mask), mask_prod(mask_prod), mask_d(mask_d) {}
};*/

/*template <class R>
struct PreprocReluGate : public PreprocGate<R> {
  std::vector<preprocg_ptr_t<BoolRing>> msb_gates;
  ReplicatedShare<R> mask_msb;
  ReplicatedShare<R> mask_w;
  ReplicatedShare<R> mask_btoa;
  ReplicatedShare<R> mask_binj;

  PreprocReluGate() = default;
  PreprocReluGate(ReplicatedShare<R> mask,
                  std::vector<preprocg_ptr_t<BoolRing>> msb_gates,
                  ReplicatedShare<R> mask_msb, ReplicatedShare<R> mask_w,
                  ReplicatedShare<R> mask_btoa, ReplicatedShare<R> mask_binj)
      : PreprocGate<R>(mask),
        msb_gates(std::move(msb_gates)),
        mask_msb(mask_msb),
        mask_w(mask_w),
        mask_btoa(mask_btoa),
        mask_binj(mask_binj) {}
};*/

/*template <class R>
struct PreprocMsbGate : public PreprocGate<R> {
  std::vector<preprocg_ptr_t<BoolRing>> msb_gates;
  ReplicatedShare<R> mask_msb;
  ReplicatedShare<R> mask_w;

  PreprocMsbGate() = default;
  PreprocMsbGate(ReplicatedShare<R> mask,
                 std::vector<preprocg_ptr_t<BoolRing>> msb_gates,
                 ReplicatedShare<R> mask_msb, ReplicatedShare<R> mask_w)
      : PreprocGate<R>(mask),
        msb_gates(std::move(msb_gates)),
        mask_msb(mask_msb),
        mask_w(mask_w) {}
};*/


//The following is not required.
//Simpler construction

// Preprocessed data for output wires.
//struct PreprocOutput {
  // Commitment corresponding to share elements not available with the party
  // for the output wire. If party's ID is 'i' then array is of the form
  // {s[i+1, i+2], s[i+1, i+3], s[i+2, i+3]}.
  //std::array<std::array<char, emp::Hash::DIGEST_SIZE>, 3> commitments{};
  //std::vector<Field> output_mask;
  // Opening info for commitments to party's output shares.
  // If party's ID is 'i' then array is of the form
  // {o[i, i+1], o[i, i+2], o[i, i+3]} where o[i, j] is the opening info for
  // share common to parties with ID i and j.
  //std::array<std::vector<uint8_t>, 3> openings;
//};

// Preprocessed data for the circuit.
template <class R>
struct PreprocCircuit {
  std::vector<preprocg_ptr_t<R>> gates;

  PreprocCircuit() = default;
  PreprocCircuit(size_t num_gates)
      : gates(num_gates) {}
        
};
};  // namespace assistedMPC
