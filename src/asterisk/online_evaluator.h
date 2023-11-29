#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "../io/netmp.h"
#include "../utils/circuit.h"
#include "preproc.h"
#include "rand_gen_pool.h"
#include "sharing.h"
#include "../utils/types.h"

using namespace common::utils;

namespace asterisk
{
  class OnlineEvaluator
  {
    int nP_;
    int id_;
    int security_param_;
    RandGenPool rgen_;
    std::shared_ptr<io::NetIOMP> network_;
    PreprocCircuit<Field> preproc_;
    common::utils::LevelOrderedCircuit circ_;
    std::vector<Field> wires_;
    std::vector<Field> q_val_;
    std::vector<AuthAddShare<Field>> q_sh_;
    common::utils::LevelOrderedCircuit multk_circ_;
    common::utils::LevelOrderedCircuit prefixOR_circ_;
    std::shared_ptr<ThreadPool> tpool_;

    // write reconstruction function
  public:
    OnlineEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                    PreprocCircuit<Field> preproc,
                    common::utils::LevelOrderedCircuit circ,
                    int security_param, int threads, int seed = 200);

    OnlineEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                    PreprocCircuit<Field> preproc,
                    common::utils::LevelOrderedCircuit circ,
                    int security_param,
                    std::shared_ptr<ThreadPool> tpool, int seed = 200);

    void setInputs(const std::unordered_map<common::utils::wire_t, Field> &inputs);

    void setRandomInputs();

    void eqzEvaluate(const std::vector<common::utils::FIn1Gate> &eqz_gates,
                     std::vector<Field> &eqz_nonTP, std::vector<AuthAddShare<Field> > &q_share, std::vector<Field> &masked_b);

    void ltzEvaluate(const std::vector<common::utils::FIn1Gate> &ltz_gates,
                     std::vector<Field> &ltz_nonTP, std::vector<AuthAddShare<Field> > &q_share, std::vector<Field> &masked_b);

    void evaluateGatesAtDepthPartySend(size_t depth,
                                       std::vector<Field> &mult_nonTP,
                                       std::vector<Field> &mult3_nonTP,
                                       std::vector<Field> &mult4_nonTP,
                                       std::vector<Field> &dotprod_nonTP);

    void evaluateGatesAtDepthPartyRecv(size_t depth,
                                       std::vector<Field> mult_all,
                                       std::vector<Field> mult3_all,
                                       std::vector<Field> mult4_all,
                                       std::vector<Field> dotprod_all,
                                       std::vector<Field> eqz_all,
                                       std::vector<AuthAddShare<Field> > eqz_q_share, std::vector<Field> eqz_masked_b,
                                       std::vector<Field> ltz_all,
                                       std::vector<AuthAddShare<Field> > ltz_q_share, std::vector<Field> ltz_masked_b);

    void evaluateGatesAtDepth(size_t depth);

    bool MACVerification();

    std::vector<Field> getOutputs();

    // Reconstruct an authenticated additive shared value
    // combining multiple values might be more effficient
    // CHECK
    Field reconstruct(AuthAddShare<Field> &shares);

    // Evaluate online phase for circuit
    std::vector<Field> evaluateCircuit(
        const std::unordered_map<common::utils::wire_t, Field> &inputs);
  };

  class BoolEvaluator
  {
    int nP_;
    int id_;
    RandGenPool rgen_;
    std::shared_ptr<io::NetIOMP> network_;
    PreprocCircuit<BoolRing> preproc_;
    common::utils::LevelOrderedCircuit circ_;
    std::vector<BoolRing> wires_;
    std::vector<BoolRing> q_val_;
    std::vector<AuthAddShare<BoolRing>> q_sh_;
    //   std::vector<BoolRing> vwires;
    //   preprocg_ptr_t<BoolRing>* vpreproc;
    //   common::utils::LevelOrderedCircuit circ;

  public:
    BoolEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                  PreprocCircuit<BoolRing> preproc,
                  common::utils::LevelOrderedCircuit circ,
                  int seed = 200);

    void setInputs(const std::unordered_map<common::utils::wire_t, BoolRing> &inputs);

    void setRandomInputs();

    //   static std::vector<BoolRing> reconstruct(
    //       int id, const std::array<std::vector<BoolRing>, 3>& recon_shares,
    //       io::NetIOMP& network, JumpProvider& jump, ThreadPool& tpool);
    void evaluateGatesAtDepthPartySend(size_t depth,
                                       std::vector<BoolRing> &mult_nonTP, std::vector<BoolRing> &r_mult_pad,
                                       std::vector<BoolRing> &mult3_nonTP, std::vector<BoolRing> &r_mult3_pad,
                                       std::vector<BoolRing> &mult4_nonTP, std::vector<BoolRing> &r_mult4_pad,
                                       std::vector<BoolRing> &dotprod_nonTP, std::vector<BoolRing> &r_dotprod_pad);
    void evaluateGatesAtDepthPartyRecv(size_t depth,
                                       std::vector<BoolRing> mult_all, std::vector<BoolRing> r_mult_pad,
                                       std::vector<BoolRing> mult3_all, std::vector<BoolRing> r_mult3_pad,
                                       std::vector<BoolRing> mult4_all, std::vector<BoolRing> r_mult4_pad,
                                       std::vector<BoolRing> dotprod_all, std::vector<BoolRing> r_dotprod_pad);
    void evaluateGatesAtDepth(size_t depth);
    void evaluateAllLevels();
    std::vector<BoolRing> getOutputs();
    std::vector<BoolRing> evaluateCircuit(const std::unordered_map<common::utils::wire_t, BoolRing> &inputs);

    //   std::vector<std::vector<BoolRing>> getOutputShares();
  };

  struct BoolEval
  {
    int id;
    int nP;
    RandGenPool rgen;
    std::vector<std::vector<BoolRing>> vwires;
    std::vector<std::vector<BoolRing>> vqval;
    std::vector<std::vector<AuthAddShare<BoolRing>>> vqsh;
    std::vector<preprocg_ptr_t<BoolRing> *> vpreproc;
    common::utils::LevelOrderedCircuit circ;

    explicit BoolEval(int my_id, int nP,
                      std::vector<preprocg_ptr_t<BoolRing> *> vpreproc,
                      common::utils::LevelOrderedCircuit circ, int seed = 200);

    // static std::vector<BoolRing> reconstruct(
    // int id, const std::array<std::vector<BoolRing>, 3>& recon_shares,
    // io::NetIOMP& network, JumpProvider& jump, ThreadPool& tpool);

    void evaluateGatesAtDepthPartySend(size_t depth,
                                       std::vector<BoolRing> &mult_nonTP, std::vector<BoolRing> &r_mult_pad,
                                       std::vector<BoolRing> &mult3_nonTP, std::vector<BoolRing> &r_mult3_pad,
                                       std::vector<BoolRing> &mult4_nonTP, std::vector<BoolRing> &r_mult4_pad,
                                       std::vector<BoolRing> &dotprod_nonTP, std::vector<BoolRing> &r_dotprod_pad, ThreadPool &tpool);

    void evaluateGatesAtDepthPartyRecv(size_t depth,
                                       std::vector<BoolRing> mult_all, std::vector<BoolRing> r_mult_pad,
                                       std::vector<BoolRing> mult3_all, std::vector<BoolRing> r_mult3_pad,
                                       std::vector<BoolRing> mult4_all, std::vector<BoolRing> r_mult4_pad,
                                       std::vector<BoolRing> dotprod_all, std::vector<BoolRing> r_dotprod_pad, ThreadPool &tpool);

    void evaluateGatesAtDepth(size_t depth, io::NetIOMP &network, ThreadPool &tpool);
    void evaluateAllLevels(io::NetIOMP &network, ThreadPool &tpool);

    std::vector<std::vector<BoolRing>> getOutputShares();
  };
}; // namespace asterisk
