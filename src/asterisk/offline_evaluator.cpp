#include "offline_evaluator.h"

#include <NTL/BasicThreadPool.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <thread>

// #include "../utils/helpers.h"

namespace asterisk {
OfflineEvaluator::OfflineEvaluator(int nP, int my_id,
                                   std::shared_ptr<io::NetIOMP> network,
                                   common::utils::LevelOrderedCircuit circ,
                                   int security_param, int threads, int seed)
    : nP_(nP),
      id_(my_id),
      security_param_(security_param),
      rgen_(my_id, seed), 
      network_(std::move(network)),
      circ_(std::move(circ)),
      preproc_(circ.num_gates)

      {tpool_ = std::make_shared<ThreadPool>(threads);}

void OfflineEvaluator::keyGen(int nP, int pid, RandGenPool& rgen, 
                      std::vector<Field>& keySh, Field& key)  {
  
  if(pid == 0) {
    key = 0;
    keySh[0] = 0;
    for(int i = 1; i <= nP; i++) {
        randomizeZZp(rgen.pi(i), keySh[i], sizeof(Field));
        key += keySh[i];
    }
  }
  else {
    randomizeZZp(rgen.p0(), key, sizeof(Field));
  }
}



void OfflineEvaluator::randomShare(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                                    AuthAddShare<Field>& share, TPShare<Field>& tpShare,
                                    Field key, std::vector<Field> keySh, std::vector<Field>& rand_sh, 
                                    size_t& idx_rand_sh) {
  // for all pid = 1 to nP sample common random value
  // pid = 0 stores values in TPShare.values
  // pid = 0 computes secret = secret()
  // pid = 0 computes tag = secret * MAC_key
  // for all pid = 1 to nP-1 sample common random tag
  // pid = 0 stores tags in TPShare.tags
  // pid = 0 sends tag[1] to pid = nP
  // std::cout << "randomShare starts" << std::endl;
  Field val = Field(0);
  Field tag = Field(0);
  Field tagn = Field(0);
  
    if(pid == 0) {
      share.pushValue(Field(0));
      share.pushTag(Field(0));
      share.setKey(keySh[0]);
      tpShare.pushValues(Field(0));
      tpShare.pushTags(Field(0));
      tpShare.setKeySh(keySh[0]);
      tpShare.setKey(key);
      
      for(int i = 1; i <= nP; i++) {

        randomizeZZp(rgen.pi(i), val, sizeof(Field));
        tpShare.pushValues(val);
        tpShare.setKeySh(keySh[i]);
        randomizeZZp(rgen.pi(i), tag, sizeof(Field));
        if( i != nP) {
          tpShare.pushTags(tag);
          tagn += tag;
          
        }
      }
      Field secret = tpShare.secret();
      
      tag = key * secret;
      tagn = tag - tagn;
      tpShare.pushTags(tagn);
      rand_sh.push_back(tagn);
    }
    else if(pid > 0) {
      share.setKey(key);
      randomizeZZp(rgen.p0(), val, sizeof(Field));
      share.pushValue(val);
      
      randomizeZZp(rgen.p0(), tag, sizeof(Field));
      
      if( pid != nP) {
        share.pushTag(tag);
      }
      else if(pid == nP) {

        share.pushTag(rand_sh[idx_rand_sh]);
        idx_rand_sh++;
        // std::cout << "inx = " << idx_rand_sh << std::endl;
      }
    }
    // std::cout << "randomShare ends" << std::endl;

}

void OfflineEvaluator::randomShareSecret(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                                  AuthAddShare<Field>& share, TPShare<Field>& tpShare,
                                  Field secret, Field key, std::vector<Field> keySh, 
                                  std::vector<Field>& rand_sh_sec, size_t& idx_rand_sh_sec) {
  // std::cout << "randomShareSecret starts" << std::endl;
  Field val = Field(0);
  Field tag = Field(0);
  Field tagn = Field(0);
  Field valn = Field(0);
  
    if(pid == 0) {
      share.pushValue(Field(0));
      share.pushTag(Field(0));
      share.setKey(keySh[0]);
      tpShare.pushValues(Field(0));
      tpShare.pushTags(Field(0));
      tpShare.setKeySh(keySh[0]);
      tpShare.setKey(key);
      for(int i = 1; i < nP; i++) {
        randomizeZZp(rgen.pi(i), val, sizeof(Field));
        tpShare.pushValues(val);
        valn += val;
        randomizeZZp(rgen.pi(i), tag, sizeof(Field));
        tpShare.pushTags(tag);
        tagn += tag;
        tpShare.setKeySh(keySh[i]);
      }
      tpShare.setKeySh(keySh[nP]);
      valn = secret - valn;
      tagn = key * secret - tagn;
      tpShare.pushValues(valn);
      tpShare.pushTags(tagn);
      rand_sh_sec.push_back(valn);
      rand_sh_sec.push_back(tagn);
    }
    else if(pid > 0) {
      share.setKey(key);
      if( pid != nP) {
        randomizeZZp(rgen.p0(), val, sizeof(Field));
        share.pushValue(val);
        randomizeZZp(rgen.p0(), tag, sizeof(Field));
        share.pushTag(tag);
      }
      else if(pid == nP) {
        valn = rand_sh_sec[idx_rand_sh_sec];
        idx_rand_sh_sec++;
        tagn = rand_sh_sec[idx_rand_sh_sec];
        idx_rand_sh_sec++;
        share.pushValue(valn);
        share.pushTag(tagn);
        // std::cout << "inx = " << idx_rand_sh_sec << std::endl;
      }
    }
    // std::cout << "randomShareSecret ends" << std::endl;
}

void OfflineEvaluator::randomShareWithParty(int nP, int pid, int dealer, RandGenPool& rgen,
                                            io::NetIOMP& network, AuthAddShare<Field>& share,
                                            TPShare<Field>& tpShare, Field& secret, Field key,
                                            std::vector<Field> keySh, std::vector<Field>& rand_sh_party, 
                                            size_t& idx_rand_sh_party) {
                                             
                                            
  Field tagF = Field(0);
  Field val = Field(0);
  Field tag = Field(0);
  Field valn = Field(0);
  Field tagn = Field(0);
  if( pid == 0) {
    if(dealer != 0) {
      randomizeZZp(rgen.pi(dealer), secret, sizeof(Field));
    }
    else {
      randomizeZZp(rgen.self(), secret, sizeof(Field));
    }
    
    share.pushValue(Field(0));
    share.pushTag(Field(0));
    share.setKey(keySh[0]);
    tpShare.pushValues(Field(0));
    tpShare.pushTags(Field(0));
    tpShare.setKeySh(keySh[0]);
    tpShare.setKey(key);
    
    tagF = key * secret;
    for(int i = 1; i < nP; i++) {
      tpShare.setKeySh(keySh[i]);
      randomizeZZp(rgen.pi(i), val, sizeof(Field));
      
      tpShare.pushValues(val);
      randomizeZZp(rgen.pi(i), tag, sizeof(Field));
      
      tpShare.pushTags(tag);
      valn += val;
      tagn += tag;
    }
    tpShare.setKeySh(keySh[nP]);
    valn = secret - valn;
    tagn = tagF - tagn;
    rand_sh_party.push_back(valn);
    rand_sh_party.push_back(tagn);
    
    tpShare.pushValues(valn);
    tpShare.pushTags(tagn);
  }
  else if ( pid > 0) {
    share.setKey(key);
    if(pid == dealer) {
      randomizeZZp(rgen.p0(), secret, sizeof(Field));
    }
    if(pid != nP) {
      randomizeZZp(rgen.p0(), val, sizeof(Field));
      share.pushValue(val);
      randomizeZZp(rgen.p0(), tag, sizeof(Field)); 
      share.pushTag(tag);
    }
    else if (pid == nP) {
      valn = rand_sh_party[idx_rand_sh_party];
      idx_rand_sh_party++;
      tagn = rand_sh_party[idx_rand_sh_party];
      idx_rand_sh_party++;
      share.pushValue(valn);
      share.pushTag(tagn);
    }
  }

}

void OfflineEvaluator::setWireMasksParty(
  const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
                    std::vector<Field>& rand_sh, std::vector<BoolRing>& b_rand_sh,
                    std::vector<Field>& rand_sh_sec, std::vector<BoolRing>& b_rand_sh_sec,
                    std::vector<Field>& rand_sh_party, std::vector<BoolRing>& b_rand_sh_party) {

    
      size_t idx_rand_sh = 0;
      size_t b_idx_rand_sh = 0;
      
      size_t idx_rand_sh_sec = 0;
      size_t b_idx_rand_sh_sec = 0;
    
      size_t idx_rand_sh_party = 0;
      size_t b_idx_rand_sh_party = 0;


    // key setup
      std::vector<Field> keySh(nP_ + 1);
      Field key = Field(0);
      if(id_ == 0)  {
        key = 0;
        keySh[0] = 0;
        for(int i = 1; i <= nP_; i++) {
            randomizeZZp(rgen_.pi(i), keySh[i], sizeof(Field));
            key += keySh[i];
        }
        key_sh_ = key;
      }
      else {
        randomizeZZp(rgen_.p0(), key, sizeof(Field));
        key_sh_ = key;
      }

      //Bool key setup
      std::vector<BoolRing> bkeySh(nP_ + 1);
      BoolRing bkey = 0;
      if(id_ == 0)  {
        bkey = 0;
        bkeySh[0] = 0;
        for(int i = 1; i <= nP_; i++) {
          uint8_t tmp;
          rgen_.pi(i).random_data(&tmp, sizeof(BoolRing));
          bkeySh[i] = tmp % 2;
          bkey += bkeySh[i];
        }
        bkey_sh_ = bkey;
      }
      else {
        uint8_t tmp;
        rgen_.p0().random_data(&tmp, sizeof(BoolRing));
        bkey = tmp % 2;
        bkey_sh_ = bkey;
      }

    // int ctr = 0;
    // int sec_ctr = 0;
    for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case common::utils::GateType::kInp: {
          auto pregate = std::make_unique<PreprocInput<Field>>();

          auto pid = input_pid_map.at(gate->out);
          pregate->pid = pid;
          randomShareWithParty(nP_, id_, pid, rgen_, *network_, pregate->mask, 
                              pregate->tpmask, pregate->mask_value, key, keySh, rand_sh_party, idx_rand_sh_party);

          preproc_.gates[gate->out] = std::move(pregate);
          
          break;
        }

        case common::utils::GateType::kAdd: {
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<Field>>((mask_in1 + mask_in2), (tpmask_in1 + tpmask_in2));

          
          break;
        }

        case common::utils::GateType::kConstAdd: {
          const auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          const auto& mask = preproc_.gates[g->in]->mask;
          const auto& tpmask = preproc_.gates[g->in]->tpmask;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<Field>>((mask), (tpmask));
          break;
        }

        case common::utils::GateType::kConstMul: {
          const auto* g = static_cast<common::utils::ConstOpGate<Field>*>(gate.get());
          const auto& mask = preproc_.gates[g->in]->mask * g->cval;
          const auto& tpmask = preproc_.gates[g->in]->tpmask * g->cval;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<Field>>((mask), (tpmask));
          break;
        }

        case common::utils::GateType::kSub: {
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<Field>>((mask_in1 - mask_in2),(tpmask_in1 - tpmask_in2));

          
          break;
        }

        case common::utils::GateType::kMul: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMultGate<Field>>();
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          Field tp_prod;
          if(id_ == 0) {tp_prod = tpmask_in1.secret() * tpmask_in2.secret();}
          TPShare<Field> tprand_mask;
          AuthAddShare<Field> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
          // std::cout << "randomShare counter = " << ctr++ << std::endl;

          TPShare<Field> tpmask_product;
          AuthAddShare<Field> mask_product; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_product, tpmask_product, tp_prod, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          // std::cout << "randomShareSecret counter = " << sec_ctr++ << std::endl;
          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMultGate<Field>>
                              (rand_mask, tprand_mask, mask_product, tpmask_product));
          
          break;
        }

        case common::utils::GateType::kMul3: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMult3Gate<Field>>();
          const auto* g = static_cast<common::utils::FIn3Gate*>(gate.get());
          
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;

          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;

          const auto& mask_in3 = preproc_.gates[g->in3]->mask;
          const auto& tpmask_in3 = preproc_.gates[g->in3]->tpmask;

          Field tp_ab, tp_ac, tp_bc, tp_abc;
          
          if(id_ == 0) {
            tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
            tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
            tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
          
            tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
          }

          TPShare<Field> tprand_mask;
          AuthAddShare<Field> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
          

          TPShare<Field> tpmask_ab;
          AuthAddShare<Field> mask_ab; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_ab, tpmask_ab, tp_ab, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_ac;
          AuthAddShare<Field> mask_ac; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_ac, tpmask_ac, tp_ac, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          TPShare<Field> tpmask_bc;
          AuthAddShare<Field> mask_bc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_bc, tpmask_bc, tp_bc, key, keySh, rand_sh_sec, idx_rand_sh_sec);
                    
          TPShare<Field> tpmask_abc;
          AuthAddShare<Field> mask_abc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_abc, tpmask_abc, tp_abc, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult3Gate<Field>>
                              (rand_mask, tprand_mask, 
                              mask_ab, tpmask_ab, 
                              mask_ac, tpmask_ac,
                              mask_bc, tpmask_bc, 
                              mask_abc, tpmask_abc));
          break;
        }

        case common::utils::GateType::kMul4: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMult4Gate<Field>>();
          const auto* g = static_cast<common::utils::FIn4Gate*>(gate.get());

          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;

          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;

          const auto& mask_in3 = preproc_.gates[g->in3]->mask;
          const auto& tpmask_in3 = preproc_.gates[g->in3]->tpmask;

          const auto& mask_in4 = preproc_.gates[g->in4]->mask;
          const auto& tpmask_in4 = preproc_.gates[g->in4]->tpmask;

          Field tp_ab, tp_ac, tp_ad, tp_bc, tp_bd, tp_cd, tp_abc, tp_abd, tp_acd, tp_bcd, tp_abcd;
          if(id_ == 0) {
            tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
            tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
            tp_ad = tpmask_in1.secret() * tpmask_in4.secret();
            tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
            tp_bd = tpmask_in2.secret() * tpmask_in4.secret();
            tp_cd = tpmask_in3.secret() * tpmask_in4.secret();
            tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
            tp_abd = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in4.secret();
            tp_acd = tpmask_in1.secret() * tpmask_in3.secret() * tpmask_in4.secret();
            tp_bcd = tpmask_in2.secret() * tpmask_in3.secret() * tpmask_in4.secret();
            tp_abcd = tpmask_in1.secret() * tpmask_in2.secret() 
                        * tpmask_in3.secret() * tpmask_in4.secret();
          }

          TPShare<Field> tprand_mask;
          AuthAddShare<Field> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, 
                          rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
          
          TPShare<Field> tpmask_ab;
          AuthAddShare<Field> mask_ab; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ab, tpmask_ab, tp_ab, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          
          TPShare<Field> tpmask_ac;
          AuthAddShare<Field> mask_ac; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ac, tpmask_ac, tp_ac, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_ad;
          AuthAddShare<Field> mask_ad; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ad, tpmask_ad, tp_ad, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_bc;
          AuthAddShare<Field> mask_bc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bc, tpmask_bc, tp_bc, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_bd;
          AuthAddShare<Field> mask_bd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bd, tpmask_bd, tp_bd, key, keySh, rand_sh_sec, idx_rand_sh_sec);
        
        
          TPShare<Field> tpmask_cd;
          AuthAddShare<Field> mask_cd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_cd, tpmask_cd, tp_cd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_abc;
          AuthAddShare<Field> mask_abc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abc, tpmask_abc, tp_abc, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          TPShare<Field> tpmask_abd;
          AuthAddShare<Field> mask_abd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abd, tpmask_abd, tp_abd, key, keySh, rand_sh_sec, idx_rand_sh_sec);
        
          TPShare<Field> tpmask_acd;
          AuthAddShare<Field> mask_acd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_acd, tpmask_acd, tp_acd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_bcd;
          AuthAddShare<Field> mask_bcd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bcd, tpmask_bcd, tp_bcd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<Field> tpmask_abcd;
          AuthAddShare<Field> mask_abcd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abcd, tpmask_abcd, tp_abcd, key, keySh, rand_sh_sec, idx_rand_sh_sec);    

          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult4Gate<Field>>
                              (rand_mask, tprand_mask, 
                              mask_ab, tpmask_ab,
                              mask_ac, tpmask_ac, 
                              mask_ad, tpmask_ad, 
                              mask_bc, tpmask_bc,
                              mask_bd, tpmask_bd,
                              mask_cd, tpmask_cd,
                              mask_abc, tpmask_abc,
                              mask_abd, tpmask_abd,
                              mask_acd, tpmask_acd,
                              mask_bcd, tpmask_bcd,
                              mask_abcd, tpmask_abcd));
          break;    
        }

        case common::utils::GateType::kDotprod: {
          preproc_.gates[gate->out] = std::make_unique<PreprocDotpGate<Field>>();
          const auto* g = static_cast<common::utils::SIMDGate*>(gate.get());
          Field mask_prod = Field(0);
          if(id_ ==0) {
            for(size_t i = 0; i < g->in1.size(); i++) {
              mask_prod += preproc_.gates[g->in1[i]]->tpmask.secret() 
                                * preproc_.gates[g->in2[i]]->tpmask.secret();
            }
          }
          TPShare<Field> tprand_mask;
          AuthAddShare<Field> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
        

          TPShare<Field> tpmask_product;
          AuthAddShare<Field> mask_product; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_product, tpmask_product, mask_prod, key, keySh, rand_sh_sec, idx_rand_sh_sec);
                                
          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocDotpGate<Field>>
                              (rand_mask, tprand_mask, mask_product, tpmask_product));
          
          break;
        }

        case common::utils::GateType::kEqz: {
          preproc_.gates[gate->out] = std::make_unique<PreprocEqzGate<Field>>();
          const auto* eqz_g = static_cast<common::utils::FIn1Gate*>(gate.get());
          // mask for the bit2A step
          AuthAddShare<Field> mask_w;
          TPShare<Field> tpmask_w;
          randomShare(nP_, id_, rgen_, *network_, mask_w, tpmask_w, key, keySh, rand_sh, idx_rand_sh);
          
          // padded_val = r - delta_x, sampled by all the parties together
          Field padded_val;
          randomizeZZp(rgen_.all(), padded_val, sizeof(Field));

          // TP obtains $r = padded_val + delta_x
          Field r_value = Field(0);
          if(id_ == 0) {
            r_value = padded_val + preproc_.gates[eqz_g->in]->tpmask.secret();
          }
          AuthAddShare<Field> rval;
          TPShare<Field> tprval;
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                rval, tprval, r_value, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          std::vector<BoolRing> r_bits(64);
          // TP bit decomposes r and shares it's bits
          if(id_ == 0) { 
            r_bits = bitDecomposeTwo(r_value);
          }
          
          // preproc for multk gate 
          auto multk_circ =
            common::utils::Circuit<BoolRing>::generateMultK().orderGatesByLevel();
   
          std::vector<preprocg_ptr_t<BoolRing>> multk_gates(multk_circ.num_gates);
          size_t inp_ctr = 0;
          for (const auto& multk_level : multk_circ.gates_by_level) {
            for (auto& multk_gate : multk_level) {
              switch (multk_gate->type) {
                case common::utils::GateType::kInp:{
                  auto* g = static_cast<common::utils::Gate*>(multk_gate.get());

                  auto pregate = std::make_unique<PreprocInput<BoolRing>>();
                  auto pid = 0;
                  auto bit_mask = r_bits[inp_ctr];
                  pregate->pid = pid;
                  pregate->mask_value = r_bits[inp_ctr];
                  
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, pregate->mask, 
                      pregate->tpmask, pregate->mask_value, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  multk_gates[g->out] = std::move(pregate);
                  inp_ctr++;
                  break;
                }
                case common::utils::GateType::kMul4:{
                  const auto* g = static_cast<common::utils::FIn4Gate*>(multk_gate.get());
                  
                  const auto& mask_in1 = multk_gates[g->in1]->mask;
                  const auto& tpmask_in1 = multk_gates[g->in1]->tpmask;

                  const auto& mask_in2 = multk_gates[g->in2]->mask;
                  const auto& tpmask_in2 = multk_gates[g->in2]->tpmask;

                  const auto& mask_in3 = multk_gates[g->in3]->mask;
                  const auto& tpmask_in3 = multk_gates[g->in3]->tpmask;

                  const auto& mask_in4 = multk_gates[g->in4]->mask;
                  const auto& tpmask_in4 = multk_gates[g->in4]->tpmask;

                  BoolRing tp_ab, tp_ac, tp_ad, tp_bc, tp_bd, tp_cd, tp_abc, tp_abd, tp_acd, tp_bcd, tp_abcd;
                  if(id_ == 0) {
                    tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
                    tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
                    tp_ad = tpmask_in1.secret() * tpmask_in4.secret();
                    tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
                    tp_bd = tpmask_in2.secret() * tpmask_in4.secret();
                    tp_cd = tpmask_in3.secret() * tpmask_in4.secret();
                    tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
                    tp_abd = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in4.secret();
                    tp_acd = tpmask_in1.secret() * tpmask_in3.secret() * tpmask_in4.secret();
                    tp_bcd = tpmask_in2.secret() * tpmask_in3.secret() * tpmask_in4.secret();
                    tp_abcd = tpmask_in1.secret() * tpmask_in2.secret() 
                                * tpmask_in3.secret() * tpmask_in4.secret();
                  }
                  

                  TPShare<BoolRing> tprand_mask;
                  AuthAddShare<BoolRing> rand_mask;
                  OfflineBoolEvaluator::randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, bkey, bkeySh, b_rand_sh, b_idx_rand_sh);
                 
                  TPShare<BoolRing> tpmask_ab;
                  AuthAddShare<BoolRing> mask_ab; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ab, tpmask_ab, tp_ab, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  
                  TPShare<BoolRing> tpmask_ac;
                  AuthAddShare<BoolRing> mask_ac; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ac, tpmask_ac, tp_ac, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_ad;
                  AuthAddShare<BoolRing> mask_ad; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ad, tpmask_ad, tp_ad, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bc;
                  AuthAddShare<BoolRing> mask_bc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_bc, tpmask_bc, tp_bc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bd;
                  AuthAddShare<BoolRing> mask_bd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_bd, tpmask_bd, tp_bd, bkey,bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                
                
                  TPShare<BoolRing> tpmask_cd;
                  AuthAddShare<BoolRing> mask_cd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_cd, tpmask_cd, tp_cd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_abc;
                  AuthAddShare<BoolRing> mask_abc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abc, tpmask_abc, tp_abc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  TPShare<BoolRing> tpmask_abd;
                  AuthAddShare<BoolRing> mask_abd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abd, tpmask_abd, tp_abd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                
                  TPShare<BoolRing> tpmask_acd;
                  AuthAddShare<BoolRing> mask_acd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_acd, tpmask_acd, tp_acd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bcd;
                  AuthAddShare<BoolRing> mask_bcd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_bcd, tpmask_bcd, tp_bcd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_abcd;
                  AuthAddShare<BoolRing> mask_abcd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abcd, tpmask_abcd, tp_abcd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  
                  multk_gates[g->out] = std::make_unique<PreprocMult4Gate<BoolRing>>(
                                      rand_mask, tprand_mask,
                                      mask_ab, tpmask_ab,
                                      mask_ac, tpmask_ac,
                                      mask_ad, tpmask_ad,
                                      mask_bc, tpmask_bc,
                                      mask_bd, tpmask_bd,
                                      mask_cd, tpmask_cd, 
                                      mask_abc, tpmask_abc,
                                      mask_abd, tpmask_abd,
                                      mask_acd, tpmask_acd,
                                      mask_bcd, tpmask_bcd,
                                      mask_abcd, tpmask_abcd);
                  
                  break;
                }
              }
            }
          }
          // The above method gives boolean output(sharing)
          // this method expects Field type values and output is also field type
          // perform Bit2A
          Field arith_b;
          AuthAddShare<Field> mask_b;
          TPShare<Field> tpmask_b;
          if(id_ == 0) { 
            auto wout = multk_circ.outputs[0];
            BoolRing bitb;
            bitb = multk_gates[wout]->tpmask.secret();
            if(bitb == 1) {arith_b = 1; }
            else { arith_b = 0;}
          }
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_b, tpmask_b, arith_b, key, keySh, rand_sh_sec, idx_rand_sh_sec);


          preproc_.gates[eqz_g->out] = std::make_unique<PreprocEqzGate<Field>>
                              (mask_w, tpmask_w, 
                              mask_b, tpmask_b, 
                              rval, tprval,
                              std::move(multk_gates), padded_val);
          break;
        }
        case common::utils::GateType::kLtz: {
          preproc_.gates[gate->out] = std::make_unique<PreprocLtzGate<Field>>();
          const auto* ltz_g = static_cast<common::utils::FIn1Gate*>(gate.get());
          // padded_val
          Field padded_val;
          randomizeZZp(rgen_.all(), padded_val, sizeof(Field));

          // TP obtains $r = padded_val + delta_x
          // TP bit decomposes r and shares it's bits
          Field r_value = Field(0);
          std::vector<BoolRing> r_bits(64);

          if(id_ == 0) {
            r_value = padded_val + preproc_.gates[ltz_g->in]->tpmask.secret();
            r_bits = bitDecomposeTwo(r_value);
          }
          
          // preproc for prefixOR gate 
          auto prefixOR_circ =
            common::utils::Circuit<BoolRing>::generateParaPrefixOR(2).orderGatesByLevel();
          
          std::vector<preprocg_ptr_t<BoolRing>> prefixOR_gates(prefixOR_circ.num_gates);
          size_t inp_ctr = 0;
          // added to save communication cost
          std::vector<PreprocInput<BoolRing>> pregates;
          for (size_t i=0; i<64; i++) {
            auto pregate = PreprocInput<BoolRing>();
            auto pid = 0;
            pregate.pid = pid;
            pregate.mask_value = r_bits[63 - i];
            OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, pregate.mask, 
                      pregate.tpmask, pregate.mask_value, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec); 
            pregates.push_back(pregate);
          }

          for (const auto& prefixOR_level : prefixOR_circ.gates_by_level) {
            for (auto& prefixOR_gate : prefixOR_level) {
              switch (prefixOR_gate->type) {
                case common::utils::GateType::kInp: {
                  auto* g = static_cast<common::utils::Gate*>(prefixOR_gate.get());
                  prefixOR_gates[g->out] = std::make_unique<PreprocInput<BoolRing>>(pregates[inp_ctr%64]);                  
                  inp_ctr++;
                  break;
                }
                case common::utils::GateType::kAdd: {
                  const auto* g = static_cast<common::utils::FIn2Gate*>(prefixOR_gate.get());
                  
                  const auto& mask_in1 = prefixOR_gates[g->in1]->mask;
                  const auto& tpmask_in1 = prefixOR_gates[g->in1]->tpmask;

                  const auto& mask_in2 = prefixOR_gates[g->in2]->mask;
                  const auto& tpmask_in2 = prefixOR_gates[g->in2]->tpmask;
                  
                  prefixOR_gates[g->out] =
                    std::make_unique<PreprocGate<BoolRing>>((mask_in1 + mask_in2), (tpmask_in1 + tpmask_in2));
                  break;
                }
                case common::utils::GateType::kSub: {
                  const auto* g = static_cast<common::utils::FIn2Gate*>(prefixOR_gate.get());
                  
                  const auto& mask_in1 = prefixOR_gates[g->in1]->mask;
                  const auto& tpmask_in1 = prefixOR_gates[g->in1]->tpmask;

                  const auto& mask_in2 = prefixOR_gates[g->in2]->mask;
                  const auto& tpmask_in2 = prefixOR_gates[g->in2]->tpmask;
                  
                  prefixOR_gates[g->out] =
                    std::make_unique<PreprocGate<BoolRing>>((mask_in1 - mask_in2), (tpmask_in1 - tpmask_in2));
                  break;
                }
                case common::utils::GateType::kConstAdd: {
                  const auto* g = static_cast<common::utils::ConstOpGate<BoolRing>*>(prefixOR_gate.get());
                  const auto& mask = prefixOR_gates[g->in]->mask;
                  const auto& tpmask = prefixOR_gates[g->in]->tpmask;
                  
                  prefixOR_gates[g->out] =
                    std::make_unique<PreprocGate<BoolRing>>((mask), (tpmask));
                  break;
                }
                case common::utils::GateType::kConstMul: {
                  const auto* g = static_cast<common::utils::ConstOpGate<BoolRing>*>(prefixOR_gate.get());
                  const auto& mask = prefixOR_gates[g->in]->mask * g->cval;
                  const auto& tpmask = prefixOR_gates[g->in]->tpmask * g->cval;
                  
                  prefixOR_gates[g->out] =
                    std::make_unique<PreprocGate<BoolRing>>((mask), (tpmask));
                  break;
                }
                case common::utils::GateType::kMul: {
                  const auto* g = static_cast<common::utils::FIn2Gate*>(prefixOR_gate.get());
                  
                  const auto& mask_in1 = prefixOR_gates[g->in1]->mask;
                  const auto& tpmask_in1 = prefixOR_gates[g->in1]->tpmask;

                  const auto& mask_in2 = prefixOR_gates[g->in2]->mask;
                  const auto& tpmask_in2 = prefixOR_gates[g->in2]->tpmask;

                  BoolRing tp_prod;
                  if(id_ == 0) {
                    tp_prod = tpmask_in1.secret() * tpmask_in2.secret();
                  }

                  TPShare<BoolRing> tprand_mask;
                  AuthAddShare<BoolRing> rand_mask;
                  OfflineBoolEvaluator::randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, bkey, bkeySh, b_rand_sh, b_idx_rand_sh);

                  TPShare<BoolRing> tpmask_prod;
                  AuthAddShare<BoolRing> mask_prod; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_prod, tpmask_prod, tp_prod, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);


                  prefixOR_gates[g->out] = std::make_unique<PreprocMultGate<BoolRing>>(
                                      rand_mask, tprand_mask,
                                      mask_prod, tpmask_prod);


                  break;
                }
                case common::utils::GateType::kMul3: {
                  const auto* g = static_cast<common::utils::FIn3Gate*>(prefixOR_gate.get());
                  
                  const auto& mask_in1 = prefixOR_gates[g->in1]->mask;
                  const auto& tpmask_in1 = prefixOR_gates[g->in1]->tpmask;

                  const auto& mask_in2 = prefixOR_gates[g->in2]->mask;
                  const auto& tpmask_in2 = prefixOR_gates[g->in2]->tpmask;

                  const auto& mask_in3 = prefixOR_gates[g->in3]->mask;
                  const auto& tpmask_in3 = prefixOR_gates[g->in3]->tpmask;

                  BoolRing tp_ab, tp_ac, tp_bc, tp_abc;
                  if(id_ == 0) {
                    tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
                    tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
                    tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
                    tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
                  }

                  TPShare<BoolRing> tprand_mask;
                  AuthAddShare<BoolRing> rand_mask;
                  OfflineBoolEvaluator::randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, bkey, bkeySh, b_rand_sh, b_idx_rand_sh);
                 
                  TPShare<BoolRing> tpmask_ab;
                  AuthAddShare<BoolRing> mask_ab; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ab, tpmask_ab, tp_ab, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  
                  TPShare<BoolRing> tpmask_ac;
                  AuthAddShare<BoolRing> mask_ac; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ac, tpmask_ac, tp_ac, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bc;
                  AuthAddShare<BoolRing> mask_bc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_bc, tpmask_bc, tp_bc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  TPShare<BoolRing> tpmask_abc;
                  AuthAddShare<BoolRing> mask_abc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abc, tpmask_abc, tp_abc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  prefixOR_gates[g->out] = std::make_unique<PreprocMult3Gate<BoolRing>>(
                                      rand_mask, tprand_mask,
                                      mask_ab, tpmask_ab,
                                      mask_ac, tpmask_ac,
                                      mask_bc, tpmask_bc,
                                      mask_abc, tpmask_abc);

                  break;
                }
                case common::utils::GateType::kMul4:{
                  const auto* g = static_cast<common::utils::FIn4Gate*>(prefixOR_gate.get());
                  
                  const auto& mask_in1 = prefixOR_gates[g->in1]->mask;
                  const auto& tpmask_in1 = prefixOR_gates[g->in1]->tpmask;

                  const auto& mask_in2 = prefixOR_gates[g->in2]->mask;
                  const auto& tpmask_in2 = prefixOR_gates[g->in2]->tpmask;

                  const auto& mask_in3 = prefixOR_gates[g->in3]->mask;
                  const auto& tpmask_in3 = prefixOR_gates[g->in3]->tpmask;

                  const auto& mask_in4 = prefixOR_gates[g->in4]->mask;
                  const auto& tpmask_in4 = prefixOR_gates[g->in4]->tpmask;

                  BoolRing tp_ab, tp_ac, tp_ad, tp_bc, tp_bd, tp_cd, tp_abc, tp_abd, tp_acd, tp_bcd, tp_abcd;
                  if(id_ == 0) {
                    tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
                    tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
                    tp_ad = tpmask_in1.secret() * tpmask_in4.secret();
                    tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
                    tp_bd = tpmask_in2.secret() * tpmask_in4.secret();
                    tp_cd = tpmask_in3.secret() * tpmask_in4.secret();
                    tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
                    tp_abd = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in4.secret();
                    tp_acd = tpmask_in1.secret() * tpmask_in3.secret() * tpmask_in4.secret();
                    tp_bcd = tpmask_in2.secret() * tpmask_in3.secret() * tpmask_in4.secret();
                    tp_abcd = tpmask_in1.secret() * tpmask_in2.secret() 
                                * tpmask_in3.secret() * tpmask_in4.secret();
                  }
                  

                  TPShare<BoolRing> tprand_mask;
                  AuthAddShare<BoolRing> rand_mask;
                  OfflineBoolEvaluator::randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, bkey, bkeySh, b_rand_sh, b_idx_rand_sh);
                 
                  TPShare<BoolRing> tpmask_ab;
                  AuthAddShare<BoolRing> mask_ab; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ab, tpmask_ab, tp_ab, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  
                  TPShare<BoolRing> tpmask_ac;
                  AuthAddShare<BoolRing> mask_ac; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ac, tpmask_ac, tp_ac, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_ad;
                  AuthAddShare<BoolRing> mask_ad; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_ad, tpmask_ad, tp_ad, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bc;
                  AuthAddShare<BoolRing> mask_bc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_bc, tpmask_bc, tp_bc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bd;
                  AuthAddShare<BoolRing> mask_bd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_bd, tpmask_bd, tp_bd, bkey,bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                
                
                  TPShare<BoolRing> tpmask_cd;
                  AuthAddShare<BoolRing> mask_cd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_cd, tpmask_cd, tp_cd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_abc;
                  AuthAddShare<BoolRing> mask_abc; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abc, tpmask_abc, tp_abc, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  TPShare<BoolRing> tpmask_abd;
                  AuthAddShare<BoolRing> mask_abd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abd, tpmask_abd, tp_abd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                
                  TPShare<BoolRing> tpmask_acd;
                  AuthAddShare<BoolRing> mask_acd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_acd, tpmask_acd, tp_acd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_bcd;
                  AuthAddShare<BoolRing> mask_bcd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_bcd, tpmask_bcd, tp_bcd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);

                  TPShare<BoolRing> tpmask_abcd;
                  AuthAddShare<BoolRing> mask_abcd; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                    mask_abcd, tpmask_abcd, tp_abcd, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);
                  
                  
                  prefixOR_gates[g->out] = std::make_unique<PreprocMult4Gate<BoolRing>>(
                                      rand_mask, tprand_mask,
                                      mask_ab, tpmask_ab,
                                      mask_ac, tpmask_ac,
                                      mask_ad, tpmask_ad,
                                      mask_bc, tpmask_bc,
                                      mask_bd, tpmask_bd,
                                      mask_cd, tpmask_cd, 
                                      mask_abc, tpmask_abc,
                                      mask_abd, tpmask_abd,
                                      mask_acd, tpmask_acd,
                                      mask_bcd, tpmask_bcd,
                                      mask_abcd, tpmask_abcd);
                  
                  break;
                }
                case common::utils::GateType::kDotprod: {
                  const auto* g = static_cast<common::utils::SIMDGate*>(prefixOR_gate.get());
                  BoolRing mask_prod = 0;
                  if(id_ == 0) {
                    for(size_t i = 0; i < g->in1.size(); i++) {
                      mask_prod += prefixOR_gates[g->in1[i]]->tpmask.secret() 
                                        * prefixOR_gates[g->in2[i]]->tpmask.secret();
                    }
                  }
                  TPShare<BoolRing> tprand_mask;
                  AuthAddShare<BoolRing> rand_mask;
                  OfflineBoolEvaluator::randomShare(nP_, id_, rgen_, *network_, rand_mask, tprand_mask, bkey, bkeySh, b_rand_sh, b_idx_rand_sh);
                

                  TPShare<BoolRing> tpmask_product;
                  AuthAddShare<BoolRing> mask_product; 
                  OfflineBoolEvaluator::randomShareSecret(nP_, id_, rgen_, *network_, 
                                  mask_product, tpmask_product, mask_prod, bkey, bkeySh, b_rand_sh_sec, b_idx_rand_sh_sec);


                  prefixOR_gates[g->out] = std::make_unique<PreprocDotpGate<BoolRing>>
                              (rand_mask, tprand_mask, mask_product, tpmask_product);
                  break;
                }
              }
            }
          }
          
          Field arith_b;
          AuthAddShare<Field> mask_b;
          TPShare<Field> tpmask_b;
          if(id_ == 0) { 
            auto wout = prefixOR_circ.outputs[0];
            BoolRing bitb;
            bitb = prefixOR_gates[wout]->tpmask.secret();
            if(bitb == 1) {arith_b = 1; }
            else { arith_b = 0;}
          }
          
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_b, tpmask_b, arith_b, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          AuthAddShare<Field> mask_w;
          TPShare<Field> tpmask_w;
          randomShare(nP_, id_, rgen_, *network_, mask_w, tpmask_w, key, keySh, rand_sh, idx_rand_sh);
          // b = m_b xor del_b = m_b + del_b - 2 m_b del_b
          // del^A_b = - 2 del_w - del_b
          // m^A_b = m_b - 2 m_w

          AuthAddShare<Field> mask_out;
          TPShare<Field> tpmask_out;

          mask_out = mask_w * Field( -2 ) + mask_b * Field( -1 );
          tpmask_out = tpmask_w * Field( -2 ) + tpmask_b * Field( -1 );
          
          preproc_.gates[ltz_g->out] = std::make_unique<PreprocLtzGate<Field>>
                                           (mask_out, tpmask_out,
                                            mask_w, tpmask_w, 
                                            mask_b, tpmask_b, 
                                            std::move(prefixOR_gates), padded_val);

          break;
        }
        
        default: {
          break;
        }
      }
    }
  }
}


void OfflineEvaluator::setWireMasks(
    const std::unordered_map<common::utils::wire_t, int>& input_pid_map) {
      
      std::vector<Field> rand_sh;
      std::vector<BoolRing> b_rand_sh;
      std::vector<Field> rand_sh_sec;
      std::vector<BoolRing> b_rand_sh_sec;
      std::vector<Field> rand_sh_party;
      std::vector<BoolRing> b_rand_sh_party;

      
  if(id_ != nP_) {
    setWireMasksParty(input_pid_map, rand_sh, b_rand_sh, rand_sh_sec, b_rand_sh_sec,
                        rand_sh_party, b_rand_sh_party);

  
    if(id_ == 0) {
      size_t rand_sh_num = rand_sh.size();
      size_t b_rand_sh_num = b_rand_sh.size();
      size_t rand_sh_sec_num = rand_sh_sec.size();
      size_t b_rand_sh_sec_num = b_rand_sh_sec.size();
      size_t rand_sh_party_num = rand_sh_party.size();
      size_t b_rand_sh_party_num = b_rand_sh_party.size();
      size_t arith_comm = rand_sh_num + rand_sh_sec_num + rand_sh_party_num;
      size_t bool_comm = b_rand_sh_num + b_rand_sh_sec_num + b_rand_sh_party_num;
      std::vector<size_t> lengths(8);
      lengths[0] = arith_comm;
      lengths[1] = rand_sh_num;
      lengths[2] = rand_sh_sec_num;
      lengths[3] = rand_sh_party_num;
      lengths[4] = bool_comm;
      lengths[5] = b_rand_sh_num;
      lengths[6] = b_rand_sh_sec_num;
      lengths[7] = b_rand_sh_party_num;



      network_->send(nP_, lengths.data(), sizeof(size_t) * 8);

      std::vector<Field> offline_arith_comm(arith_comm);
      std::vector<BoolRing> offline_bool_comm(bool_comm);
      for(size_t i = 0; i < rand_sh_num; i++) {
        offline_arith_comm[i] = rand_sh[i];
      }
      for(size_t i = 0; i < rand_sh_sec_num; i++) {
        offline_arith_comm[rand_sh_num + i] = rand_sh_sec[i];
      }
      for(size_t i = 0; i < rand_sh_party_num; i++) {
        offline_arith_comm[rand_sh_sec_num + rand_sh_num + i] = rand_sh_party[i];
      }
      for(size_t i = 0; i < b_rand_sh_num; i++) {
        offline_bool_comm[i] = b_rand_sh[i];
      }
      for(size_t i = 0; i < b_rand_sh_sec_num; i++) {
        offline_bool_comm[b_rand_sh_num + i] = b_rand_sh_sec[i];
      }
      for(size_t i = 0; i < b_rand_sh_party_num; i++) {
        offline_bool_comm[b_rand_sh_sec_num + b_rand_sh_num + i] = b_rand_sh_party[i];
      }
      auto net_data = BoolRing::pack(offline_bool_comm.data(), bool_comm);
      network_->send(nP_, offline_arith_comm.data(), sizeof(Field) * arith_comm);
      network_->send(nP_, net_data.data(), sizeof(uint8_t) * net_data.size());
      // network_->send(nP_, offline_bool_comm.data(), sizeof(BoolRing) * bool_comm);
    }
  }
  else if(id_ == nP_ ) {
    std::vector<size_t> lengths(8);
    
    network_->recv(0, lengths.data(), sizeof(size_t) * 8);
    
    size_t arith_comm = lengths[0];
    size_t rand_sh_num = lengths[1];
    size_t rand_sh_sec_num = lengths[2];
    size_t rand_sh_party_num = lengths[3];
    size_t bool_comm = lengths[4];
    size_t b_rand_sh_num = lengths[5];
    size_t b_rand_sh_sec_num = lengths[6];
    size_t b_rand_sh_party_num = lengths[7];


    std::vector<Field> offline_arith_comm(arith_comm);
    network_->recv(0, offline_arith_comm.data(), sizeof(Field) * arith_comm);
    size_t nbytes = (bool_comm + 7) / 8;
    std::vector<uint8_t> net_data(nbytes);
    network_->recv(0, net_data.data(), nbytes * sizeof(uint8_t));
    auto offline_bool_comm = BoolRing::unpack(net_data.data(), bool_comm);
    // std::vector<BoolRing> offline_bool_comm(bool_comm);
    // network_->recv(0, offline_bool_comm.data(), sizeof(BoolRing) * bool_comm);
    

    rand_sh.resize(rand_sh_num);
    for(int i = 0; i < rand_sh_num; i++) {
      rand_sh[i] = offline_arith_comm[i];
    }
    
    rand_sh_sec.resize(rand_sh_sec_num);
    for(int i = 0; i < rand_sh_sec_num; i++) {
      rand_sh_sec[i] = offline_arith_comm[rand_sh_num + i];
    }
    
    rand_sh_party.resize(rand_sh_party_num);
    for(int i = 0; i < rand_sh_party_num; i++) {
      rand_sh_party[i] = offline_arith_comm[rand_sh_num + rand_sh_sec_num + i];
    }
    
    b_rand_sh.resize(b_rand_sh_num);
    for(int i = 0; i < b_rand_sh_num; i++) {
      b_rand_sh[i] = offline_bool_comm[i];
    }
    
    b_rand_sh_sec.resize(b_rand_sh_sec_num);
    for(int i = 0; i < b_rand_sh_sec_num; i++) {
      b_rand_sh_sec[i] = offline_bool_comm[b_rand_sh_num + i];
    }
    
    b_rand_sh_party.resize(b_rand_sh_party_num);
    for(int i = 0; i < b_rand_sh_party_num; i++) {
      b_rand_sh_party[i] = offline_bool_comm[b_rand_sh_num + b_rand_sh_sec_num + i];
    }
    
    setWireMasksParty(input_pid_map, rand_sh, b_rand_sh, rand_sh_sec, b_rand_sh_sec,
                        rand_sh_party, b_rand_sh_party);
  }
  
}

void OfflineEvaluator::getOutputMasks(int pid, std::vector<Field>& output_mask) { 
  output_mask.clear();
  if(circ_.outputs.empty()) {
    return;
  }
  
  
  if(pid == 0){
    for(size_t i = 0; i < circ_.outputs.size(); i++) {
      output_mask.push_back(preproc_.gates[circ_.outputs[i]]->tpmask.secret());
    }
    
  }
  else {
    for(size_t i = 0; i < circ_.outputs.size(); i++) {
    output_mask.push_back(Field(0));
    }
  }
  
}

PreprocCircuit<Field> OfflineEvaluator::getPreproc() {
  return std::move(preproc_);
}

PreprocCircuit<Field> OfflineEvaluator::run(
    const std::unordered_map<common::utils::wire_t, int>& input_pid_map) {
  setWireMasks(input_pid_map);

  return std::move(preproc_);
  
}

OfflineBoolEvaluator::OfflineBoolEvaluator(int nP, int my_id, std::shared_ptr<io::NetIOMP> network,
                   common::utils::LevelOrderedCircuit circ, int seed)
  : nP_(nP),
    id_(my_id),
    rgen_(my_id, seed),
    network_(std::move(network)),
    circ_(std::move(circ)),
    preproc_(circ.num_gates) {}


void OfflineBoolEvaluator::randomShare(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                                    AuthAddShare<BoolRing>& share, TPShare<BoolRing>& tpShare,
                                    BoolRing key, std::vector<BoolRing> keySh, std::vector<BoolRing>& rand_sh, 
                                    size_t& idx_rand_sh) {
  // for all pid = 1 to nP sample common random value
  // pid = 0 stores values in TPShare.values
  // pid = 0 computes secret = secret()
  // pid = 0 computes tag = secret * MAC_key
  // for all pid = 1 to nP-1 sample common random tag
  // pid = 0 stores tags in TPShare.tags
  // pid = 0 sends tag[1] to pid = nP
  
  BoolRing val = 0;
  BoolRing tag = 0;
  BoolRing tagn = 0;
    if(pid == 0) {
      share.pushValue(0);
      share.pushTag(0);
      share.setKey(keySh[0]);
      tpShare.pushValues(0);
      tpShare.pushTags(0);
      tpShare.setKeySh(keySh[0]);
      tpShare.setKey(key);
      
      for(int i = 1; i <= nP; i++) {
        uint8_t tmp;
        rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
        val = tmp % 2;
        tpShare.pushValues(val);
        tpShare.setKeySh(keySh[i]);
        rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
        tag = tmp % 2;
        if( i != nP) {
          tpShare.pushTags(tag);
          tagn += tag;
          
        }
      }
      BoolRing secret = tpShare.secret();
      tag = key * secret;
      tagn = tag - tagn;
      tpShare.pushTags(tagn);
      rand_sh.push_back(tagn);
    }
    else if(pid > 0) {
      share.setKey(key);
      uint8_t tmp;
      rgen.p0().random_data(&tmp, sizeof(BoolRing));
      val = tmp % 2;
      share.pushValue(val);
      
      rgen.p0().random_data(&tmp, sizeof(BoolRing));
      tag = tmp % 2;
      if( pid != nP) {
        share.pushTag(tag);
      }
      else if(pid == nP) {

        share.pushTag(rand_sh[idx_rand_sh]);
        idx_rand_sh++;
      }
    }

}

void OfflineBoolEvaluator::randomShareSecret(int nP, int pid, RandGenPool& rgen, io::NetIOMP& network,
                                  AuthAddShare<BoolRing>& share, TPShare<BoolRing>& tpShare,
                                  BoolRing secret, BoolRing key, std::vector<BoolRing> keySh, 
                                  std::vector<BoolRing>& rand_sh_sec, size_t& idx_rand_sh_sec) {
  BoolRing val = 0;
  BoolRing tag = 0;
  BoolRing tagn = 0;
  BoolRing valn = 0;
  
    if(pid == 0) {
      share.pushValue(0);
      share.pushTag(0);
      share.setKey(keySh[0]);
      tpShare.pushValues(0);
      tpShare.pushTags(0);
      tpShare.setKeySh(keySh[0]);
      tpShare.setKey(key);
      for(int i = 1; i < nP; i++) {
        uint8_t tmp;
        rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
        val = tmp % 2; 
        tpShare.pushValues(val);
        valn += val;
        rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
        tag = tmp % 2;
        tpShare.pushTags(tag);
        tagn += tag;
        tpShare.setKeySh(keySh[i]);
      }
      tpShare.setKeySh(keySh[nP]);
      valn = secret - valn;
      tagn = key * secret - tagn;
      tpShare.pushValues(valn);
      tpShare.pushTags(tagn);
      rand_sh_sec.push_back(valn);
      rand_sh_sec.push_back(tagn);
    }
    else if(pid > 0) {
      share.setKey(key);
      if( pid != nP) {
        uint8_t tmp;
        rgen.p0().random_data(&tmp, sizeof(BoolRing));
        val = tmp % 2;
        share.pushValue(val);
        rgen.p0().random_data(&tmp, sizeof(BoolRing));
        tag = tmp % 2;
        share.pushTag(tag);
      }
      else if(pid == nP) {
        valn = rand_sh_sec[idx_rand_sh_sec];
        idx_rand_sh_sec++;
        tagn = rand_sh_sec[idx_rand_sh_sec];
        idx_rand_sh_sec++;
        share.pushValue(valn);
        share.pushTag(tagn);
      }
    }
}

void OfflineBoolEvaluator::randomShareWithParty(int nP, int pid, int dealer, RandGenPool& rgen,
                                            io::NetIOMP& network, AuthAddShare<BoolRing>& share,
                                            TPShare<BoolRing>& tpShare, BoolRing& secret, BoolRing key,
                                            std::vector<BoolRing> keySh, std::vector<BoolRing>& rand_sh_party, 
                                            size_t& idx_rand_sh_party) {
                                             
                                            
  BoolRing tagF = 0;
  BoolRing val = 0;
  BoolRing tag = 0;
  BoolRing valn = 0;
  BoolRing tagn = 0;
  if( pid == 0) {
    if(dealer != 0) {
      uint8_t tmp;
      rgen.pi(dealer).random_data(&tmp, sizeof(BoolRing));
      secret = tmp % 2;
    }
    else {
      uint8_t tmp;
      rgen.self().random_data(&tmp, sizeof(BoolRing));
      secret = tmp % 2;
    }
    
    share.pushValue(0);
    share.pushTag(0);
    share.setKey(keySh[0]);
    tpShare.pushValues(0);
    tpShare.pushTags(0);
    tpShare.setKeySh(keySh[0]);
    tpShare.setKey(key);
    
    tagF = key * secret;
    for(int i = 1; i < nP; i++) {
      tpShare.setKeySh(keySh[i]);
      uint8_t tmp; 
      rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
      val = tmp % 2;
      
      tpShare.pushValues(val);
      rgen.pi(i).random_data(&tmp, sizeof(BoolRing));
      tag = tmp % 2;

      tpShare.pushTags(tag);
      valn += val;
      tagn += tag;
    }
    tpShare.setKeySh(keySh[nP]);
    valn = secret - valn;
    tagn = tagF - tagn;
    rand_sh_party.push_back(valn);
    rand_sh_party.push_back(tagn);
    
    tpShare.pushValues(valn);
    tpShare.pushTags(tagn);
  }
  else if ( pid > 0) {
    share.setKey(key);
    uint8_t tmp;
    if(pid == dealer) {
      rgen.p0().random_data(&tmp, sizeof(BoolRing));
      secret = tmp % 2;
    }
    if(pid != nP) {
      rgen.p0().random_data(&tmp, sizeof(BoolRing));
      val = tmp % 2;
      share.pushValue(val);
      rgen.p0().random_data(&tmp, sizeof(BoolRing)); 
      tag = tmp  % 2;
      share.pushTag(tag);
    }
    else if (pid == nP) {
      valn = rand_sh_party[idx_rand_sh_party];
      idx_rand_sh_party++;
      tagn = rand_sh_party[idx_rand_sh_party];
      idx_rand_sh_party++;
      share.pushValue(valn);
      share.pushTag(tagn);
    }
  }
}

void OfflineBoolEvaluator::setWireMasksParty(
  const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
  const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map,
                    std::vector<BoolRing>& rand_sh, 
                    std::vector<BoolRing>& rand_sh_sec, 
                    std::vector<BoolRing>& rand_sh_party) {

      
      size_t idx_rand_sh = 0;
      
      
      size_t idx_rand_sh_sec = 0;

    
      size_t idx_rand_sh_party = 0;

    // key setup
      std::vector<BoolRing> keySh(nP_ + 1);
      BoolRing key = 0;
      if(id_ == 0)  {
        uint8_t tmp;
        key = 0;
        keySh[0] = 0;
        for(int i = 1; i <= nP_; i++) {
            rgen_.pi(i).random_data(&tmp, sizeof(BoolRing));
            keySh[i] = tmp % 2;
            key += keySh[i];
        }
        key_sh_ = key;
      }
      else {
        uint8_t tmp;
        rgen_.p0().random_data(&tmp, sizeof(BoolRing));
        key = tmp % 2;
        key_sh_ = key;
      }
      
    for (const auto& level : circ_.gates_by_level) {
    for (const auto& gate : level) {
      switch (gate->type) {
        case common::utils::GateType::kInp: {
          auto pregate = std::make_unique<PreprocInput<BoolRing>>();
          auto pid = input_pid_map.at(gate->out);
          auto bit_mask = bit_mask_map.at(gate->out);
          pregate->pid = pid;
          if(pid != 0 ) {
            randomShareWithParty(nP_, id_, pid, rgen_, *network_, pregate->mask, 
                              pregate->tpmask, pregate->mask_value, key, keySh, rand_sh_party, idx_rand_sh_party);

            preproc_.gates[gate->out] = std::move(pregate);
          }
          else if(pid == 0) {
            randomShareSecret(nP_, id_, rgen_, *network_, pregate->mask, 
                      pregate->tpmask, bit_mask, key, keySh, rand_sh_sec, idx_rand_sh_sec);
            
            preproc_.gates[gate->out] = std::move(pregate);
          }
          break;
        }

        case common::utils::GateType::kConstAdd: {
          const auto* g = static_cast<common::utils::ConstOpGate<BoolRing>*>(gate.get());
          const auto& mask = preproc_.gates[g->in]->mask;
          const auto& tpmask = preproc_.gates[g->in]->tpmask;
          preproc_.gates[g->out] = 
                std::make_unique<PreprocGate<BoolRing>>((mask), (tpmask));
          break;
        }
        
        case common::utils::GateType::kConstMul: {
          const auto* g = static_cast<common::utils::ConstOpGate<BoolRing>*>(gate.get());
          const auto& mask = preproc_.gates[g->in]->mask * g->cval;
          const auto& tpmask = preproc_.gates[g->in]->tpmask * g->cval;
          preproc_.gates[g->out] = 
                std::make_unique<PreprocGate<BoolRing>>((mask), (tpmask));
          break;
        }

        case common::utils::GateType::kAdd: {
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<BoolRing>>((mask_in1 + mask_in2), (tpmask_in1 + tpmask_in2));

          
          break;
        }

        case common::utils::GateType::kSub: {
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          preproc_.gates[gate->out] =
              std::make_unique<PreprocGate<BoolRing>>((mask_in1 - mask_in2),(tpmask_in1 - tpmask_in2));

          
          break;
        }

        case common::utils::GateType::kMul: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMultGate<BoolRing>>();
          const auto* g = static_cast<common::utils::FIn2Gate*>(gate.get());
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;
          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;
          BoolRing tp_prod;
          if(id_ == 0) {tp_prod = tpmask_in1.secret() * tpmask_in2.secret();}
          TPShare<BoolRing> tprand_mask;
          AuthAddShare<BoolRing> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
                    
          TPShare<BoolRing> tpmask_product;
          AuthAddShare<BoolRing> mask_product; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_product, tpmask_product, tp_prod, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMultGate<BoolRing>>
                              (rand_mask, tprand_mask, mask_product, tpmask_product));
          
          break;
        }

        case common::utils::GateType::kMul3: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMult3Gate<BoolRing>>();
          const auto* g = static_cast<common::utils::FIn3Gate*>(gate.get());
          
          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;

          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;

          const auto& mask_in3 = preproc_.gates[g->in3]->mask;
          const auto& tpmask_in3 = preproc_.gates[g->in3]->tpmask;

          BoolRing tp_ab, tp_ac, tp_bc, tp_abc;
          
          if(id_ == 0) {
            tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
            tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
            tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
          
            tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
          }

          TPShare<BoolRing> tprand_mask;
          AuthAddShare<BoolRing> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, 
                                  rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
          

          TPShare<BoolRing> tpmask_ab;
          AuthAddShare<BoolRing> mask_ab; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_ab, tpmask_ab, tp_ab, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_ac;
          AuthAddShare<BoolRing> mask_ac; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_ac, tpmask_ac, tp_ac, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          TPShare<BoolRing> tpmask_bc;
          AuthAddShare<BoolRing> mask_bc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_bc, tpmask_bc, tp_bc, key, keySh, rand_sh_sec, idx_rand_sh_sec);
                    
          TPShare<BoolRing> tpmask_abc;
          AuthAddShare<BoolRing> mask_abc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_abc, tpmask_abc, tp_abc, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult3Gate<BoolRing>>
                              (rand_mask, tprand_mask, 
                              mask_ab, tpmask_ab, 
                              mask_ac, tpmask_ac,
                              mask_bc, tpmask_bc, 
                              mask_abc, tpmask_abc));
          break;
        }

        case common::utils::GateType::kMul4: {
          preproc_.gates[gate->out] = std::make_unique<PreprocMult4Gate<BoolRing>>();
          const auto* g = static_cast<common::utils::FIn4Gate*>(gate.get());

          const auto& mask_in1 = preproc_.gates[g->in1]->mask;
          const auto& tpmask_in1 = preproc_.gates[g->in1]->tpmask;

          const auto& mask_in2 = preproc_.gates[g->in2]->mask;
          const auto& tpmask_in2 = preproc_.gates[g->in2]->tpmask;

          const auto& mask_in3 = preproc_.gates[g->in3]->mask;
          const auto& tpmask_in3 = preproc_.gates[g->in3]->tpmask;

          const auto& mask_in4 = preproc_.gates[g->in4]->mask;
          const auto& tpmask_in4 = preproc_.gates[g->in4]->tpmask;

          BoolRing tp_ab, tp_ac, tp_ad, tp_bc, tp_bd, tp_cd, tp_abc, tp_abd, tp_acd, tp_bcd, tp_abcd;
          if(id_ == 0) {
            tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
            tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
            tp_ad = tpmask_in1.secret() * tpmask_in4.secret();
            tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
            tp_bd = tpmask_in2.secret() * tpmask_in4.secret();
            tp_cd = tpmask_in3.secret() * tpmask_in4.secret();
            tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
            tp_abd = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in4.secret();
            tp_acd = tpmask_in1.secret() * tpmask_in3.secret() * tpmask_in4.secret();
            tp_bcd = tpmask_in2.secret() * tpmask_in3.secret() * tpmask_in4.secret();
            tp_abcd = tpmask_in1.secret() * tpmask_in2.secret() 
                        * tpmask_in3.secret() * tpmask_in4.secret();
          }

          TPShare<BoolRing> tprand_mask;
          AuthAddShare<BoolRing> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, 
                          rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
          
          TPShare<BoolRing> tpmask_ab;
          AuthAddShare<BoolRing> mask_ab; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ab, tpmask_ab, tp_ab, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          
          TPShare<BoolRing> tpmask_ac;
          AuthAddShare<BoolRing> mask_ac; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ac, tpmask_ac, tp_ac, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_ad;
          AuthAddShare<BoolRing> mask_ad; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                          mask_ad, tpmask_ad, tp_ad, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_bc;
          AuthAddShare<BoolRing> mask_bc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bc, tpmask_bc, tp_bc, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_bd;
          AuthAddShare<BoolRing> mask_bd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bd, tpmask_bd, tp_bd, key, keySh, rand_sh_sec, idx_rand_sh_sec);
        
        
          TPShare<BoolRing> tpmask_cd;
          AuthAddShare<BoolRing> mask_cd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_cd, tpmask_cd, tp_cd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_abc;
          AuthAddShare<BoolRing> mask_abc; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abc, tpmask_abc, tp_abc, key, keySh, rand_sh_sec, idx_rand_sh_sec);
          
          TPShare<BoolRing> tpmask_abd;
          AuthAddShare<BoolRing> mask_abd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abd, tpmask_abd, tp_abd, key, keySh, rand_sh_sec, idx_rand_sh_sec);
        
          TPShare<BoolRing> tpmask_acd;
          AuthAddShare<BoolRing> mask_acd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_acd, tpmask_acd, tp_acd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_bcd;
          AuthAddShare<BoolRing> mask_bcd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_bcd, tpmask_bcd, tp_bcd, key, keySh, rand_sh_sec, idx_rand_sh_sec);

          TPShare<BoolRing> tpmask_abcd;
          AuthAddShare<BoolRing> mask_abcd; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                            mask_abcd, tpmask_abcd, tp_abcd, key, keySh, rand_sh_sec, idx_rand_sh_sec);    

          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult4Gate<BoolRing>>
                              (rand_mask, tprand_mask, 
                              mask_ab, tpmask_ab,
                              mask_ac, tpmask_ac, 
                              mask_ad, tpmask_ad, 
                              mask_bc, tpmask_bc,
                              mask_bd, tpmask_bd,
                              mask_cd, tpmask_cd,
                              mask_abc, tpmask_abc,
                              mask_abd, tpmask_abd,
                              mask_acd, tpmask_acd,
                              mask_bcd, tpmask_bcd,
                              mask_abcd, tpmask_abcd));
          break;    
        }

        case common::utils::GateType::kDotprod: {
          preproc_.gates[gate->out] = std::make_unique<PreprocDotpGate<BoolRing>>();
          const auto* g = static_cast<common::utils::SIMDGate*>(gate.get());
          BoolRing mask_prod = 0;
          if(id_ ==0) {
            for(size_t i = 0; i < g->in1.size(); i++) {
              mask_prod += preproc_.gates[g->in1[i]]->tpmask.secret() 
                                * preproc_.gates[g->in2[i]]->tpmask.secret();
            }
          }
          TPShare<BoolRing> tprand_mask;
          AuthAddShare<BoolRing> rand_mask;
          randomShare(nP_, id_, rgen_, *network_, rand_mask, tprand_mask, key, keySh, rand_sh, idx_rand_sh);
        

          TPShare<BoolRing> tpmask_product;
          AuthAddShare<BoolRing> mask_product; 
          randomShareSecret(nP_, id_, rgen_, *network_, 
                                mask_product, tpmask_product, mask_prod, key, keySh, rand_sh_sec, idx_rand_sh_sec);
                                
          preproc_.gates[gate->out] = std::move(std::make_unique<PreprocDotpGate<BoolRing>>
                              (rand_mask, tprand_mask, mask_product, tpmask_product));
          
          break;
        }
        
        default: {
          break;
        }
      }
    }
  }
}

void OfflineBoolEvaluator::setWireMasks(
    const std::unordered_map<common::utils::wire_t, int>& input_pid_map,
    const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map) {
      
      std::vector<BoolRing> rand_sh;
      size_t idx_rand_sh;
      
      std::vector<BoolRing> rand_sh_sec;
      size_t idx_rand_sh_sec;

      std::vector<BoolRing> rand_sh_party;
      size_t idx_rand_sh_party;

  
      
  if(id_ != nP_) {
    setWireMasksParty(input_pid_map, bit_mask_map, rand_sh, rand_sh_sec, rand_sh_party);
  
    if(id_ == 0) {
      size_t rand_sh_num = rand_sh.size();
      size_t rand_sh_sec_num = rand_sh_sec.size();
      size_t rand_sh_party_num = rand_sh_party.size();
      size_t total_comm = rand_sh_num + rand_sh_sec_num + rand_sh_party_num;
      std::vector<size_t> lengths(4);
      lengths[0] = total_comm;
      lengths[1] = rand_sh_num;
      lengths[2] = rand_sh_sec_num;
      lengths[3] = rand_sh_party_num;

      network_->send(nP_, lengths.data(), sizeof(size_t) * 4);

      std::vector<BoolRing> offline_comm(total_comm);
      for(size_t i = 0; i < rand_sh_num; i++) {
        offline_comm[i] = rand_sh[i];
      }
      for(size_t i = 0; i < rand_sh_sec_num; i++) {
        offline_comm[rand_sh_num + i] = rand_sh_sec[i];
      }
      for(size_t i = 0; i < rand_sh_party_num; i++) {
        offline_comm[rand_sh_sec_num + rand_sh_num + i] = rand_sh_party[i];
      }
      network_->send(nP_, offline_comm.data(), sizeof(BoolRing) * total_comm);
    }
  }
  else if(id_ == nP_ ) {
    std::vector<size_t> lengths(4);
    
    network_->recv(0, lengths.data(), sizeof(size_t) * 4);
    
    size_t total_comm = lengths[0];
    size_t rand_sh_num = lengths[1];
    size_t rand_sh_sec_num = lengths[2];
    size_t rand_sh_party_num = lengths[3];

    std::vector<BoolRing> offline_comm(total_comm);

    network_->recv(0, offline_comm.data(), sizeof(BoolRing) * total_comm);
    
    rand_sh.resize(rand_sh_num);
    
    for(int i = 0; i < rand_sh_num; i++) {
      rand_sh[i] = offline_comm[i];
    }

    rand_sh_sec.resize(rand_sh_sec_num);
    
    for(int i = 0; i < rand_sh_sec_num; i++) {
      rand_sh_sec[i] = offline_comm[rand_sh_num + i];
    }
    
    rand_sh_party.resize(rand_sh_party_num);
    
    for(int i = 0; i < rand_sh_party_num; i++) {
      rand_sh_party[i] = offline_comm[rand_sh_num + rand_sh_sec_num + i];
    }
    setWireMasksParty(input_pid_map, bit_mask_map, rand_sh, rand_sh_sec, rand_sh_party);
  }
}

void OfflineBoolEvaluator::getOutputMasks(std::vector<AuthAddShare<BoolRing>>& output_masks,
                                          std::vector<TPShare<BoolRing>>& output_tpmasks) { 
  output_masks.clear();
  output_tpmasks.clear();
  if(circ_.outputs.empty()) {
    return;
  }
  else{
    for(size_t i = 0; i < circ_.outputs.size(); i++) {
      output_masks.push_back(preproc_.gates[circ_.outputs[i]]->mask);
      if(id_ == 0) {
        output_tpmasks.push_back(preproc_.gates[circ_.outputs[i]]->tpmask);
      }
    }
  }
}

PreprocCircuit<BoolRing> OfflineBoolEvaluator::getPreproc() {
  return std::move(preproc_);
}

PreprocCircuit<BoolRing> OfflineBoolEvaluator::run(
    const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
    const std::unordered_map<common::utils::wire_t, BoolRing>& bit_mask_map,
    std::vector<AuthAddShare<BoolRing>>& output_mask,
    std::vector<TPShare<BoolRing>>& output_tpmask) {
      
  setWireMasks(input_pid_map, bit_mask_map);
  getOutputMasks(output_mask, output_tpmask);
  return std::move(preproc_);
  
}
};  // namespace asterisk
