#define BOOST_TEST_MODULE online
#include <emp-tool/emp-tool.h>
#include <io/netmp.h>
#include <asterisk/offline_evaluator.h>
#include <asterisk/online_evaluator.h>
#include <asterisk/sharing.h>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/included/unit_test.hpp>
#include <cmath>
#include <future>
#include <memory>
#include <string>
#include <vector>
#include <thread>

using namespace asterisk;
using namespace common::utils;
namespace bdata = boost::unit_test::data;
constexpr int TEST_DATA_MAX_VAL = 1000;
constexpr int SECURITY_PARAM = 128;

struct GlobalFixture {
  GlobalFixture() {
    NTL::ZZ_p::init(NTL::conv<NTL::ZZ>("17816577890427308801"));
  }
};

BOOST_GLOBAL_FIXTURE(GlobalFixture);

BOOST_AUTO_TEST_SUITE(online_evaluator)

BOOST_AUTO_TEST_CASE(mult) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 2; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    
    inputs[winp] = Field(distrib(gen));
  }
  auto w_amb =
     circ.addGate(common::utils::GateType::kMul, input_wires[0], input_wires[1]);
  
  circ.setAsOutput(w_amb);
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(exp_output == output);
      }
      i++;
  }
  
}


BOOST_AUTO_TEST_CASE(EQZ_zero) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 2; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    
    inputs[winp] = 0;
  }
  auto w_eqz =
     circ.addGate(common::utils::GateType::kEqz, input_wires[0]);
  auto w_mul = circ.addGate(common::utils::GateType::kMul, w_eqz, input_wires[1]);
  auto w_out = circ.addGate(common::utils::GateType::kEqz, w_mul);
  circ.setAsOutput(w_eqz);
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(output == exp_output);
      }
      i++;
  }
  // std::cout<< "EQZ_zero completed succcessfully " << std::endl;
}


BOOST_AUTO_TEST_CASE(EQZ_non_zero) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 2; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    inputs[winp] = 30234235;
  }
  auto w_eqz =
     circ.addGate(common::utils::GateType::kEqz, input_wires[0]);
  
  circ.setAsOutput(w_eqz);
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      // std::cout<< "party id = " << i <<std::endl;
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        // BOOST_TEST(output[0] == 1);
        BOOST_TEST(output == exp_output);
      }
      i++;
  }
  // std::cout<< "EQZ_non_zero completed succcessfully " << std::endl;

}

BOOST_AUTO_TEST_CASE(LTZ) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;
  int numLTZ = 2;

  for (size_t i = 0; i < numLTZ; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;    
    inputs[winp] = Field(distrib(gen));
    auto w_ltz = circ.addGate(common::utils::GateType::kLtz, input_wires[i]);
    circ.setAsOutput(w_ltz);
  }
  inputs[input_wires[0]] = -4; inputs[input_wires[1]] = 40;
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, nP);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(output == exp_output);
      }
      i++;
  }
}

BOOST_AUTO_TEST_CASE(depth_2_circuit) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 10;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    
    inputs[winp] = Field(distrib(gen));
  }
  auto w_aab =
     circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
     circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
  auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
  auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
   circ.setAsOutput(w_cmd);
   circ.setAsOutput(w_mout);
   circ.setAsOutput(w_aout);
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;  
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(exp_output == output);
      }
      i++;
  }
  
}



BOOST_AUTO_TEST_CASE(dotp_gate) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  auto seed = emp::makeBlock(100, 200);
  int nf = 10;
  int nP = 5;
  Circuit<Field> circ;
  std::vector<wire_t> vwa(nf);
  std::vector<wire_t> vwb(nf);
  for (int i = 0; i < nf; i++) {
    vwa[i] = circ.newInputWire();
    vwb[i] = circ.newInputWire();
  }
  auto wdotp = circ.addGate(GateType::kDotprod, vwa, vwb);
  circ.setAsOutput(wdotp);
  auto level_circ = circ.orderGatesByLevel();

  std::unordered_map<wire_t, Field> input_map;
  std::unordered_map<wire_t, int> input_pid_map;
  std::mt19937 gen(200);
  std::uniform_int_distribution<Ring> distrib(0, TEST_DATA_MAX_VAL);
  for (size_t i = 0; i < nf; ++i) {
    input_map[vwa[i]] = distrib(gen);
    input_map[vwb[i]] = distrib(gen);
    input_pid_map[vwa[i]] = 1;
    input_pid_map[vwb[i]] = 2;
  }

  auto exp_output = circ.evaluate(input_map);

  std::vector<std::future<std::vector<Field>>> parties;
  //std::vector<std::future<PreprocCircuit<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
    parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, input_map]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);

      auto preproc = eval.run(input_pid_map);
      
      network->sync();

      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                   level_circ, SECURITY_PARAM, 1);

      return online_eval.evaluateCircuit(input_map);
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    if(i > 0) {
      auto output = p.get();
      BOOST_TEST(output == exp_output);
    }
    i++;
  }
}


BOOST_AUTO_TEST_CASE(mult3) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 4; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    
    inputs[winp] = Field(distrib(gen));
    
  }
  auto w_aab =
     circ.addGate(common::utils::GateType::kAdd, input_wires[0], input_wires[1]);
  auto w_cmd =
      circ.addGate(common::utils::GateType::kMul, input_wires[2], input_wires[3]);
  auto w_mout = circ.addGate(common::utils::GateType::kMul, w_aab, w_cmd);
  auto w_aout = circ.addGate(common::utils::GateType::kAdd, w_aab, w_cmd);
  auto w_mul_th = circ.addGate(common::utils::GateType::kMul3, w_aab, w_cmd, w_mout);
   circ.setAsOutput(w_cmd);
   circ.setAsOutput(w_mout);
   circ.setAsOutput(w_aout);
   circ.setAsOutput(w_mul_th);

  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
         BOOST_TEST(exp_output == output);
      }
      i++;
  }
  
}


BOOST_AUTO_TEST_CASE(mult4_2) {
  NTL::ZZ_pContext ZZ_p_ctx;
  ZZ_p_ctx.save();
  int nP = 4;
  auto seed_block = emp::makeBlock(0, 200);
  emp::PRG prg(&seed_block);
  std::mt19937 gen(200);
  std::uniform_int_distribution<uint> distrib(0, TEST_DATA_MAX_VAL);
  common::utils::Circuit<Field> circ;
  std::vector<common::utils::wire_t> input_wires;
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, Field> inputs;

  for (size_t i = 0; i < 8; ++i) {
    auto winp = circ.newInputWire();
    input_wires.push_back(winp);
    input_pid_map[winp] = 1;
    
    // inputs[winp] = distrib(gen);
    inputs[winp] = Field(1);
  }

  auto w_m1 = circ.addGate(common::utils::GateType::kMul, input_wires[0], input_wires[1]);
  auto w_m3_2 = circ.addGate(common::utils::GateType::kMul3, input_wires[2], input_wires[3], w_m1);
  auto w_m3_3 = circ.addGate(common::utils::GateType::kMul3, input_wires[4], input_wires[5], w_m1);
  auto w_m4_1 = circ.addGate(common::utils::GateType::kMul4, input_wires[6], input_wires[7], w_m1, w_m3_2);
  auto w_m4_2 = circ.addGate(common::utils::GateType::kMul4, input_wires[6], input_wires[7], w_m1, w_m3_3);
  auto w_m2 = circ.addGate(common::utils::GateType::kMul, input_wires[0], w_m4_2);
  circ.setAsOutput(w_m1);
  circ.setAsOutput(w_m4_1);
  circ.setAsOutput(w_m2);

  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  
  std::vector<std::future<std::vector<Field>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      ZZ_p_ctx.restore();
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineEvaluator eval(nP, i, network, 
                            level_circ, SECURITY_PARAM, 4);
      auto preproc = eval.run(input_pid_map);
      
      network->sync();
     
      OnlineEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ, SECURITY_PARAM, 1);
      
      auto res = online_eval.evaluateCircuit(inputs);
      return res;
      
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(exp_output == output);

        // std::cout<<"exp_output = " << exp_output[exp_output.size() - 1] << " output = " << output[output.size() - 1] << std::endl;
      }
      i++;
  }

}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(online_bool_evaluator)

BOOST_AUTO_TEST_CASE(Multk_bool) {
  int nP = 5;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generateMultK();
  std::unordered_map<common::utils::wire_t, int> input_pid_map(64);
  std::unordered_map<common::utils::wire_t, BoolRing> input_map(64);
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map(64);
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>>   output_tpmask;
  // BoolRing exp_output = 1;
   for (size_t i = 0; i < 64; ++i) {
    input_map[i] = 1;
    input_pid_map[i] = 1;
    bit_mask_map[i] = 0;
    // exp_output *= input_map[i];
  }
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(input_map);
  std::vector<std::future<std::vector<BoolRing>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, input_map]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, network, level_circ);
      
      auto preproc = eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
      
      network->sync();
      
      BoolEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ);
      
      auto res =  online_eval.evaluateCircuit(input_map);
      return res;
    }));
  }

  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(exp_output == output);
      }
      i++;
  }
}



BOOST_AUTO_TEST_CASE(PrefixAND) {
  int nP = 4;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generatePrefixAND();
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> inputs;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>>   output_tpmask;
  for(size_t i = 0; i < 2 * 64; i++) {
    input_pid_map[i] = 1;
    bit_mask_map[i] = 0; 
    inputs[i] = 1;
  }
  inputs[60] = 0;
  inputs[62] = 0; 
  std::vector<BoolRing> prod(64);
  for(size_t i = 0; i < 64; i++) {
    inputs[i + 64] = rand() % 2;
    prod[i] = inputs[0];
    for(size_t j = 0; j <= i; j++) {
      prod[i] *= inputs[j];
    }
  }
  auto level_circ = circ.orderGatesByLevel();
  auto exp_output = circ.evaluate(inputs);
  auto exp_out = inputs[124];
  std::vector<std::future<std::vector<BoolRing>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, network, level_circ);
      auto preproc = eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
      
      network->sync();
      BoolEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ);
      
      auto res =  online_eval.evaluateCircuit(inputs);
      return res;
    }));
  }
  int i = 0;
  for (auto& p : parties) {
    auto output = p.get();
      if(i > 0) {
        BOOST_TEST(exp_output == output);
      }
      i++;
  }
}

BOOST_AUTO_TEST_CASE(ParaPrefixAND) {
  int nP = 4;
  int repeat =2;
  int k = 64;
  common::utils::Circuit<BoolRing> circ = common::utils::Circuit<BoolRing>::generateParaPrefixAND(repeat);
  std::unordered_map<common::utils::wire_t, int> input_pid_map;
  std::unordered_map<common::utils::wire_t, BoolRing> inputs;
  std::unordered_map<common::utils::wire_t, BoolRing> bit_mask_map;
  std::vector<AuthAddShare<BoolRing>> output_mask;
  std::vector<TPShare<BoolRing>>   output_tpmask;
  for (int rep = 0; rep < repeat; rep++) {
    for(size_t i = 0; i <= k; i++) {
      input_pid_map[(rep*(k+1)) + i] = 1;
      inputs[(rep*(k+1)) + i] = 1;
      bit_mask_map[(rep*(k+1)) + i] = 0; 
    }
  }
  auto level_circ = circ.orderGatesByLevel();
  std::vector<std::future<std::vector<BoolRing>>> parties;
  parties.reserve(nP+1);
  for (int i = 0; i <= nP; ++i) {
      parties.push_back(std::async(std::launch::async, [&, i, input_pid_map, inputs]() {
      
      auto network = std::make_shared<io::NetIOMP>(i, nP+1, 10000, nullptr, true);
      
      OfflineBoolEvaluator eval(nP, i, network, level_circ);
      auto preproc = eval.run(input_pid_map, bit_mask_map, output_mask, output_tpmask);
      
      network->sync();
      BoolEvaluator online_eval(nP, i, std::move(network), std::move(preproc),
                                  level_circ);
      
          auto res =  online_eval.evaluateCircuit(inputs);
            
      // auto res = online_eval.evaluateCircuit(inputs);
      return res;
    }));
  }
}

BOOST_AUTO_TEST_SUITE_END()
