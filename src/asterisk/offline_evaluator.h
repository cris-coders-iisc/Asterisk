#pragma once

#include <emp-tool/emp-tool.h>

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>

#include "../io/netmp.h"
#include "../utils/circuit.h"


#include "preproc.h"
#include "asterisk/rand_gen_pool.h"
#include "sharing.h"
#include "../utils/types.h"

using namespace common::utils;

namespace asterisk {
class OfflineEvaluator {
  int nP_;  
  int id_;
  int security_param_;
  Field key_sh_;
  BoolRing bkey_sh_;
  RandGenPool rgen_;
  std::shared_ptr<io::NetIOMP> network_;
  common::utils::LevelOrderedCircuit circ_;
  std::shared_ptr<ThreadPool> tpool_;
  PreprocCircuit<Field> preproc_;
  
  


  // Used for running common coin protocol. Returns common random PRG key which
  // is then used to generate randomness for common coin output.
  //emp::block commonCoinKey();

 public:
  
  OfflineEvaluator(int nP, int my_id, std::shared_ptr<io::NetIOMP> network,
                   common::utils::LevelOrderedCircuit circ, int security_param,
                   int threads, int seed = 200);

  static void keyGen(int nP, int pid, RandGenPool& rgen, 
                      std::vector<Field>& keySh, Field& key);   

  // Generate sharing of a random unknown value.
  static void randomShare(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                          AuthAddShare<Field>& share, TPShare<Field>& tpShare, Field key, 
                          std::vector<Field> keySh, std::vector<Field>& rand_sh, size_t& idx_rand_sh);
  // Generate sharing of a random value known to dealer (called by all parties
  // except the dealer).
  //static void randomShareWithParty(int pid, int dealer=0, RandGenPool& rgen,
  //                                 io::NetIOMP& network,
  //                                 ReplicatedShare<Field>& share);
  // Generate sharing of a random value known to party. Should be called by
  // dealer when other parties call other variant.
  static void randomShareSecret(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                                   AuthAddShare<Field>& share, TPShare<Field>& tpShare, Field secret,
                                   Field key, std::vector<Field> keySh, std::vector<Field>& rand_sh_sec, size_t& idx_rand_sh_sec);


  static void randomShareWithParty(int nP, int pid, int dealer, RandGenPool& rgen,
                                  io::NetIOMP& network, AuthAddShare<Field>& share,
                                  TPShare<Field>& tpShare, Field& secret, Field key,
                                  std::vector<Field> keySh, std::vector<Field>& rand_sh_party, size_t& idx_rand_sh_party); 
                                          
                                           

  // Following methods implement various preprocessing subprotocols.

  // Set masks for each wire. Should be called before running any of the other
  // subprotocols.
  void setWireMasksParty(const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
          std::vector<Field>& rand_sh, std::vector<BoolRing>& b_rand_sh,
          std::vector<Field>& rand_sh_sec, std::vector<BoolRing>& b_rand_sh_sec,
          std::vector<Field>& rand_sh_party, std::vector<BoolRing>& b_rand_sh_party);

  void setWireMasks(const std::unordered_map<common::utils::wire_t, int>& input_pid_map);
  
  void getOutputMasks(int pid, std::vector<Field>& output_mask);

  PreprocCircuit<Field> getPreproc();

  // Efficiently runs above subprotocols.
  PreprocCircuit<Field> run(
      const std::unordered_map<common::utils::wire_t, int>& input_pid_map);

  
};

class OfflineBoolEvaluator {
  int nP_;  
  int id_;
  BoolRing key_sh_;
  RandGenPool rgen_;
  std::shared_ptr<io::NetIOMP> network_;
  common::utils::LevelOrderedCircuit circ_;
  PreprocCircuit<BoolRing> preproc_;
  

  public:
  
  OfflineBoolEvaluator(int nP, int my_id, std::shared_ptr<io::NetIOMP> network,
                   common::utils::LevelOrderedCircuit circ, int seed = 200);


  static void randomShare(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                          AuthAddShare<BoolRing>& share, TPShare<BoolRing>& tpShare, BoolRing key, 
                          std::vector<BoolRing> keySh, std::vector<BoolRing>& rand_sh, size_t& idx_rand_sh);
  
  
  static void randomShareSecret(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                          AuthAddShare<BoolRing>& share, TPShare<BoolRing>& tpShare, BoolRing secret,
                          BoolRing key, std::vector<BoolRing> keySh, std::vector<BoolRing>& rand_sh_sec, size_t& idx_rand_sh_sec);


  static void randomShareWithParty(int nP, int pid, int dealer, RandGenPool& rgen, io::NetIOMP& network,
                          AuthAddShare<BoolRing>& share, TPShare<BoolRing>& tpShare, BoolRing& secret, 
                          BoolRing key, std::vector<BoolRing> keySh, std::vector<BoolRing>& rand_sh_party, size_t& idx_rand_sh_party);
                                  

  void setWireMasksParty(const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
          const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map,
          std::vector<BoolRing>& rand_sh, std::vector<BoolRing>& rand_sh_sec, std::vector<BoolRing>& rand_sh_party);

  void setWireMasks(const std::unordered_map<common::utils::wire_t, int>& input_pid_map,
                    const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map);
  
  void getOutputMasks(std::vector<AuthAddShare<BoolRing>>& output_masks,
                 std::vector<TPShare<BoolRing>>& output_tpmasks);

  PreprocCircuit<BoolRing> getPreproc();
   
  PreprocCircuit<BoolRing> run(
      const std::unordered_map<common::utils::wire_t, int>& input_pid_map,
      const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map,
      std::vector<AuthAddShare<BoolRing>>& output_mask,
      std::vector<TPShare<BoolRing>>& output_tpmask);

};
};  // namespace asterisk
