#define BOOST_TEST_MODULE offline

#include <emp-tool/emp-tool.h>
#include <io/netmp.h>
#include <utils/helpers.h>
#include <asterisk/offline_evaluator.h>
#include <asterisk/rand_gen_pool.h>
#include <utils/circuit.h>

#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/included/unit_test.hpp>
#include <future>
#include <memory>
#include <random>
#include <vector>

using namespace asterisk;
namespace bdata = boost::unit_test::data;
 

constexpr int TEST_DATA_MAX_VAL = 1000;
constexpr int SECURITY_PARAM = 128;

struct GlobalFixture {
  GlobalFixture() {
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>("17816577890427308801"));
  }
};

BOOST_GLOBAL_FIXTURE(GlobalFixture);


BOOST_AUTO_TEST_SUITE(offline_evaluator)

BOOST_AUTO_TEST_CASE(random_share) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  
  
  std::vector<std::future<AuthAddShare<Field>>> parties;
  
   TPShare<Field> tpshares;
  for (int i = 0; i <= nP; i++) {
    
    
    parties.push_back(std::async(std::launch::async, [&, i]() { 
      ZZ_p_ctx.restore();
      AuthAddShare<Field> shares;
      

      std::vector<Field> rand_sh;
      size_t idx = 0;
      RandGenPool vrgen(i, nP);

      std::vector<Field> keySh(nP + 1);
      Field key = Field(0);
      if(i == 0)  {
        key = 0;
        keySh[0] = 0;
        for(int j = 1; j <= nP; j++) {
            randomizeZZp(vrgen.pi(j), keySh[j], sizeof(Field));
            key += keySh[j];
        }
      
      }
      else {
        randomizeZZp(vrgen.p0(), key, sizeof(Field));
      }

      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      if(i != nP) {
      OfflineEvaluator::randomShare(nP, i, vrgen, *network, 
                                 shares, tpshares, key, keySh, rand_sh, idx);
        if(i == 0) {
          size_t rand_sh_num = rand_sh.size();
          network->send(nP, &rand_sh_num, sizeof(size_t));
          network->send(nP, rand_sh.data(), sizeof(Field) * rand_sh_num);
        }
      }
      else {
        size_t rand_sh_num;
        
        network->recv(0, &rand_sh_num, sizeof(size_t));
        rand_sh.resize(rand_sh_num);
        network->recv(0, rand_sh.data(), sizeof(Field) * rand_sh_num);
        OfflineEvaluator::randomShare(nP, i, vrgen, *network, 
                                  shares, tpshares, key, keySh, rand_sh, idx);
      }

      return shares;
    }));
    
  }
  int i = 0;
  for (auto& p : parties) { 
    auto res = p.get();
      
        BOOST_TEST(res.valueAt() == tpshares.commonValueWithParty(i));
        BOOST_TEST(res.tagAt() == tpshares.commonTagWithParty(i));
     
      i++;
    }
  }
 
BOOST_AUTO_TEST_CASE(EQZ) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
  }


  auto w_eq = circ.addGate(common::utils::GateType::kEqz, input_wires[0]);
  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aab, Field(2));
      auto w_cons_m = circ.addConstOpGate(common::utils::GateType::kConstMul, w_cmd, Field(2));
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cons);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      // auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aout, 2);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  circ.setAsOutput(w_eq);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  std::vector<Field> keySh(nP + 1);
  Field key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      RandGenPool vrgen(i, nP);
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 1);
      return eval.run(input_pid_map);
      
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}

BOOST_AUTO_TEST_CASE(LTZ) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
  }


  auto w_lt = circ.addGate(common::utils::GateType::kLtz, input_wires[0]);
  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aab, Field(2));
      auto w_cons_m = circ.addConstOpGate(common::utils::GateType::kConstMul, w_cmd, Field(2));
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cons);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      // auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aout, 2);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  circ.setAsOutput(w_lt);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  std::vector<Field> keySh(nP + 1);
  Field key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      RandGenPool vrgen(i, nP);
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 1);
      return eval.run(input_pid_map);
      
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}



BOOST_AUTO_TEST_CASE(depth_2_circuit) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
  }



  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aab, Field(2));
      auto w_cons_m = circ.addConstOpGate(common::utils::GateType::kConstMul, w_cmd, Field(2));
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cons);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      // auto w_cons = circ.addConstOpGate(common::utils::GateType::kConstAdd, w_aout, 2);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  std::vector<Field> keySh(nP + 1);
  Field key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      RandGenPool vrgen(i, nP);
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 1);
      return eval.run(input_pid_map);
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}

BOOST_AUTO_TEST_CASE(Mult3) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
  }

  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      auto w_mul_th = circ.addGate(common::utils::GateType::kMul3, w_aab, w_cmd, w_mout);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  circ.setAsOutput(w_mul_th);
  auto level_circ = circ.orderGatesByLevel();

  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      RandGenPool vrgen(i, nP);
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 1);
      return eval.run(input_pid_map);
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}




BOOST_AUTO_TEST_CASE(Mult4) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
  }
  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      auto w_mul_f = circ.addGate(common::utils::GateType::kMul4, w_aab, w_cmd, w_mout, w_aout);
      auto w_mul_d = circ.addGate(common::utils::GateType::kMul4, w_aab, w_cmd, w_mout, w_mul_f);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  circ.setAsOutput(w_mul_f);
  circ.setAsOutput(w_mul_d);
  auto level_circ = circ.orderGatesByLevel();
  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      RandGenPool vrgen(i, nP);
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 1);
      return eval.run(input_pid_map);
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}



BOOST_AUTO_TEST_CASE(dot_product) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  auto seed = emp::makeBlock(100, 200);
  int nf = 10;
  int nP = 5;
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> vwa(nf);
  std::vector<common::utils::wire_t> vwb(nf);
  for (int i = 0; i < nf; i++) {
    vwa[i] = circ.newInputWire();
    vwb[i] = circ.newInputWire();
  }
  auto wdotp = circ.addGate(common::utils::GateType::kDotprod, vwa, vwb);
  circ.setAsOutput(wdotp);
  auto level_circ = circ.orderGatesByLevel();

  std::unordered_map<common::utils::wire_t, Field> input_map;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  for (size_t i = 0; i < nf; ++i) {
    input_map[vwa[i]] = Field(distrib(gen));
    input_map[vwb[i]] = Field(distrib(gen));
    input_pid_map[vwa[i]] = 0;
    input_pid_map[vwb[i]] = 1;
  }

  auto exp_output = circ.evaluate(input_map);

  std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  std::vector<Field> keySh(nP + 1);
  Field key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      ZZ_p_ctx.restore();
      RandGenPool vrgen(i, nP);
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, std::move(network), 
                            level_circ, SECURITY_PARAM, 4);
      
      return eval.run(input_pid_map);
    }));
  }

  std::vector<PreprocCircuit<Field>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}


BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(offline_bool_evaluator)

BOOST_AUTO_TEST_CASE(depth_2_bool_circuit) {
  int nP = 5;
  common::utils::Circuit<BoolRing> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    bit_mask_map[winp] = 0;
  }



  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;
  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  std::vector<BoolRing> keySh(nP + 1);
  BoolRing key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      RandGenPool vrgen(i, nP);
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
    }));
  }

  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}

BOOST_AUTO_TEST_CASE(Mult4_bool) {
  int nP = 5;
  common::utils::Circuit<BoolRing> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    bit_mask_map[winp] = 0;
  }
  auto w_aab =
      circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
      auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
      auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
      auto w_mul_f = circ.addGate(common::utils::GateType::kMul4, w_aab, w_cmd, w_mout, w_aout);
  circ.setAsOutput(w_mout);
  circ.setAsOutput(w_aout);
  circ.setAsOutput(w_mul_f);
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;

  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      RandGenPool vrgen(i, nP);
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
    }));
  }

  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}



BOOST_AUTO_TEST_CASE(dot_product_bool) {
  auto seed = emp::makeBlock(100, 200);
  int nf = 10;
  int nP = 5;
  common::utils::Circuit<BoolRing> circ;
  std::vector<common::utils::wire_t> vwa(nf);
  std::vector<common::utils::wire_t> vwb(nf);
  for (int i = 0; i < nf; i++) {
    vwa[i] = circ.newInputWire();
    vwb[i] = circ.newInputWire();
  }
  auto wdotp = circ.addGate(common::utils::GateType::kDotprod, vwa, vwb);
  circ.setAsOutput(wdotp);
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;

  std::unordered_map<common::utils::wire_t, BoolRing> input_map;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  // std::mt19937 gen(200);
  // std::uniform_int_distribution<BoolRing> distrib(0, TEST_DATA_MAX_VAL);
  for (size_t i = 0; i < nf; ++i) {
    input_map[vwa[i]] = 1;
    input_map[vwb[i]] = 1;
    input_pid_map[vwa[i]] = 0;
    input_pid_map[vwb[i]] = 1;
    bit_mask_map[vwa[i]] = 0;
    bit_mask_map[vwb[i]] = 0;
  }

  // auto exp_output = circ.evaluate(input_map);

  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  std::vector<BoolRing> keySh(nP + 1);
  BoolRing key;
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      RandGenPool vrgen(i, nP);
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
    }));
  }

  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
  
  for (int i = 1; i <= nP; ++i) {
    BOOST_TEST(v_preproc[i].gates.size() == level_circ.num_gates);
    const auto& preproc_i = v_preproc[i];
    for(int j = 0; j < 4; j++) {
      auto tpmask = preproc_0.gates[j]->tpmask;
      auto mask_i = preproc_i.gates[j]->mask;
      BOOST_TEST(mask_i.valueAt() == tpmask.commonValueWithParty(i));
      BOOST_TEST(mask_i.tagAt() == tpmask.commonTagWithParty(i));
    }
  }
}


BOOST_AUTO_TEST_CASE(PrefixAND) {
  int nP = 5;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generatePrefixAND();
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;

  std::unordered_map<common::utils::wire_t, BoolRing> input_map;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;

  for (size_t i = 0; i < 2 * 64; ++i) {
    input_map[i] = 1;
    input_pid_map[i] = 1;
    bit_mask_map[i] = 0;
  }

  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
    }));
  }
  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
}

BOOST_AUTO_TEST_CASE(ParaPrefixAND) {
  int nP = 5;
  int repeat = 2;
  int k = 64;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generateParaPrefixAND(repeat);
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;

  std::unordered_map<common::utils::wire_t, BoolRing> input_map;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  for(size_t j = 0; j < repeat; j++ ) {
    for (size_t i = 0; i < k; ++i) {
      input_map[(j * k) +i] = 1;
      input_pid_map[(j * k) + i] = 1;
      bit_mask_map[(j * k) + i] = 0;
    }
  }

  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
      
    }));
  }
  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
}


BOOST_AUTO_TEST_CASE(Multk) {
  int nP = 5;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generateMultK();
  auto level_circ = circ.orderGatesByLevel();
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>> output_tpmask;

  std::unordered_map<common::utils::wire_t, BoolRing> input_map;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;

  for (size_t i = 0; i <= 64; ++i) {
    input_map[i] = 1;
    input_pid_map[i] = 1;
    bit_mask_map[i] = 0;
  }

  std::vector<std::future<PreprocCircuit<BoolRing>>> parties;
  parties.reserve(nP+1);
  
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, std::move(network), level_circ);
      
      return eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
    }));
  }
  std::vector<PreprocCircuit<BoolRing>> v_preproc;
  v_preproc.reserve(parties.size());
  for (auto& f : parties) {
    v_preproc.push_back(f.get());
  }

  BOOST_TEST(v_preproc[0].gates.size() == level_circ.num_gates);
  const auto& preproc_0 = v_preproc[0];
}

BOOST_AUTO_TEST_SUITE_END()
