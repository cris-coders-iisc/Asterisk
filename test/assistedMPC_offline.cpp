#define BOOST_TEST_MODULE offline

#include <emp-tool/emp-tool.h>
#include <io/netmp.h>
#include <utils/helpers.h>
#include <assistedMPC/offline_evaluator.h>
#include <assistedMPC/rand_gen_pool.h>
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

using namespace assistedMPC;
namespace bdata = boost::unit_test::data;
 

constexpr int TEST_DATA_MAX_VAL = 1000;
constexpr int SECURITY_PARAM = 128;

struct GlobalFixture {
  GlobalFixture() {
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>("17816577890427308801"));
  }
};

void randomizeZZpTwo(emp::PRG& prg, NTL::ZZ_p& val, int nbytes) {
    uint64_t var;
    prg.random_data(&var, nbytes);
    std::cout << "Value is: " << var << " " << val << std::endl;
    val = var;
}

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
      if(i == 0) { 
        std::vector<std::vector<Field>> rand_sh(nP + 1);
        OfflineEvaluator::randomShare_Helper(nP, vrgen, shares, tpshares, key, keySh, rand_sh);
        size_t rand_sh_num = rand_sh[1].size();
        for(size_t j = 1; j <= nP; j++) {
            network->send(j, &rand_sh_num, sizeof(size_t));
            network->send(j, rand_sh[j-1].data(), sizeof(Field) * rand_sh_num);
        }
      }
      else {
        size_t rand_sh_num;
        network->recv(0, &rand_sh_num, sizeof(size_t));
        std::vector<Field> rand_sh(rand_sh_num);
        network->recv(0, rand_sh.data(), sizeof(Field) * rand_sh_num);
        OfflineEvaluator::randomShare_Party(shares, key, rand_sh, idx);
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

BOOST_AUTO_TEST_CASE(random_share_secret) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  
  std::vector<std::future<AuthAddShare<Field>>> parties;
  TPShare<Field> tpshares;
  for (int i = 0; i <= nP; i++) {
    parties.push_back(std::async(std::launch::async, [&, i]() { 
      ZZ_p_ctx.restore();
      AuthAddShare<Field> shares;
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
      if(i == 0) { 
        Field secret;
        randomizeZZp(vrgen.self(), secret, sizeof(Field));
        std::vector<std::vector<Field>> rand_sh_sec(nP + 1);
        OfflineEvaluator::randomShareSecret_Helper(nP, vrgen, shares, tpshares, secret, key, keySh, rand_sh_sec);
        size_t rand_sh_sec_num = rand_sh_sec[1].size();
        for(size_t j = 1; j <= nP; j++) {
            network->send(j, &rand_sh_sec_num, sizeof(size_t));
            network->send(j, rand_sh_sec[j-1].data(), sizeof(Field) * rand_sh_sec_num);
        }
      }
      else {
        size_t rand_sh_sec_num;
        network->recv(0, &rand_sh_sec_num, sizeof(size_t));
        std::vector<Field> rand_sh_sec(rand_sh_sec_num);
        network->recv(0, rand_sh_sec.data(), sizeof(Field) * rand_sh_sec_num);
        OfflineEvaluator::randomShare_Party(shares, key, rand_sh_sec, idx);
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

BOOST_AUTO_TEST_CASE(random_share_party) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 5;
  int dealer = 1;
  std::vector<std::future<AuthAddShare<Field>>> parties;
  TPShare<Field> tpshares;
  for (int i = 0; i <= nP; i++) {
    parties.push_back(std::async(std::launch::async, [&, i]() { 
      ZZ_p_ctx.restore();
      AuthAddShare<Field> shares;
      
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
      if(i == 0) { 
        std::vector<std::vector<Field>> rand_sh_party(nP + 1);
        OfflineEvaluator::randomShareWithParty_Helper(nP, dealer, vrgen, shares, tpshares, key, keySh, rand_sh_party);
        for(size_t j = 1; j <= nP; j++) {
          size_t rand_sh_party_num = rand_sh_party[j - 1].size();
            network->send(j, &rand_sh_party_num, sizeof(size_t));
            network->send(j, rand_sh_party[j-1].data(), sizeof(Field) * rand_sh_party_num);
        }
      }
      else {
        size_t idx = 0;
        size_t rand_sh_party_num;
        network->recv(0, &rand_sh_party_num, sizeof(size_t));
        std::vector<Field> rand_sh_party(rand_sh_party_num);
        network->recv(0, rand_sh_party.data(), sizeof(Field) * rand_sh_party_num);
        if(i == dealer) {
          Field secret;
          OfflineEvaluator::randomShareWithParty_Dealer(secret, shares, key, rand_sh_party, idx);
        }
        else {
          OfflineEvaluator::randomShareWithParty_Party(shares, key, rand_sh_party, idx);
        }        
      }

      return shares;
    }));
    
  }
  int i = 0;
  for (auto& p : parties) { 
    auto res = p.get();
        if(i != dealer) {
          BOOST_TEST(res.valueAt() == tpshares.commonValueWithParty(i));
          BOOST_TEST(res.tagAt() == tpshares.commonTagWithParty(i));
        }
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
  BOOST_AUTO_TEST_SUITE_END()
