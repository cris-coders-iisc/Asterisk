#include "offline_evaluator.h"

#include <NTL/BasicThreadPool.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <thread>


namespace assistedMPC {
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



    void OfflineEvaluator::randomShare_Helper(int nP, RandGenPool& rgen,
            AuthAddShare<Field>& share, TPShare<Field>& tpShare,
            Field key, std::vector<Field> keySh, std::vector<std::vector<Field>>& rand_sh) {

        Field secret = Field(0);
        randomizeZZp(rgen.self(), secret, sizeof(Field));
        randomShareSecret_Helper(nP, rgen, share, tpShare, secret, key, keySh, rand_sh);
    }

    void OfflineEvaluator::randomShare_Party(AuthAddShare<Field>& share,
            Field key, std::vector<Field>& rand_sh, size_t& idx_rand_sh) {

        share.setKey(key);
        share.pushValue(rand_sh[idx_rand_sh]);
        idx_rand_sh++;
        share.pushTag(rand_sh[idx_rand_sh]);
        idx_rand_sh++;

    }

    void OfflineEvaluator::randomShareSecret_Helper(int nP, RandGenPool& rgen, 
            AuthAddShare<Field>& share, TPShare<Field>& tpShare,
            Field secret, Field key, std::vector<Field> keySh, 
            std::vector<std::vector<Field>>& rand_sh_sec) {

        Field val = Field(0);
        Field tag = Field(0);
        Field tagn = Field(0);
        Field valn = Field(0);

        share.pushValue(Field(0));
        share.pushTag(Field(0));
        share.setKey(keySh[0]);
        tpShare.pushValues(Field(0));
        tpShare.pushTags(Field(0));
        tpShare.setKeySh(keySh[0]);
        tpShare.setKey(key);
        for(int i = 1; i < nP; i++) {
            randomizeZZp(rgen.self(), val, sizeof(Field));
            tpShare.pushValues(val);
            rand_sh_sec[i-1].push_back(val);
            valn += val;
            randomizeZZp(rgen.self(), tag, sizeof(Field));
            tpShare.pushTags(tag);
            rand_sh_sec[i-1].push_back(tag);
            tagn += tag;
            tpShare.setKeySh(keySh[i]);
        }
        tpShare.setKeySh(keySh[nP]);
        valn = secret - valn;
        tagn = key * secret - tagn;
        tpShare.pushValues(valn);
        rand_sh_sec[nP-1].push_back(valn);
        tpShare.pushTags(tagn);
        rand_sh_sec[nP-1].push_back(tagn);

    }

    void OfflineEvaluator::randomShareSecret_Party(AuthAddShare<Field>& share,
            Field key, std::vector<Field>& rand_sh_sec, size_t& idx_rand_sh_sec) {

        randomShare_Party(share, key, rand_sh_sec, idx_rand_sh_sec);
    }

    void OfflineEvaluator::randomShareWithParty_Helper(int nP, int dealer, RandGenPool& rgen,
            AuthAddShare<Field>& share, TPShare<Field>& tpShare, Field key,
            std::vector<Field> keySh, std::vector<std::vector<Field>>& rand_sh_party) {

        Field secret = Field(0);
        randomizeZZp(rgen.self(), secret, sizeof(Field));
        randomShareSecret_Helper(nP, rgen, share, tpShare, secret, key, keySh, rand_sh_party);
        rand_sh_party[dealer-1].push_back(secret);

    }

    void OfflineEvaluator::randomShareWithParty_Party(AuthAddShare<Field>& share,
            Field key, std::vector<Field>& rand_sh_party, size_t& idx_rand_sh_party) {

        randomShare_Party(share, key, rand_sh_party, idx_rand_sh_party);
    }

    void OfflineEvaluator::randomShareWithParty_Dealer(Field& secret, AuthAddShare<Field>& share,
            Field key, std::vector<Field>& rand_sh_party, size_t& idx_rand_sh_party) {

        randomShare_Party(share, key, rand_sh_party, idx_rand_sh_party);
        secret = rand_sh_party[idx_rand_sh_party];
        idx_rand_sh_party++;
    }

    void OfflineEvaluator::setWireMasksHelper(
            const std::unordered_map<common::utils::wire_t, int>& input_pid_map, 
            std::vector<std::vector<Field>>& rand_sh, std::vector<std::vector<BoolRing>>& b_rand_sh,
            std::vector<std::vector<Field>>& rand_sh_sec, std::vector<std::vector<BoolRing>>& b_rand_sh_sec,
            std::vector<std::vector<Field>>& rand_sh_party, std::vector<std::vector<BoolRing>>& b_rand_sh_party) {


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


        for (const auto& level : circ_.gates_by_level) {
            for (const auto& gate : level) {
                switch (gate->type) {
                    case common::utils::GateType::kInp: {
                        auto pregate = std::make_unique<PreprocInput<Field>>();
                        auto pid = input_pid_map.at(gate->out);
                        pregate->pid = pid;
                        randomShareWithParty_Helper(nP_, pid, rgen_, pregate->mask, pregate->tpmask, key, keySh, rand_sh_party);
                        pregate->mask_value = pregate->tpmask.secret();
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
                        Field tp_prod = tpmask_in1.secret() * tpmask_in2.secret();
                        TPShare<Field> tprand_mask;
                        AuthAddShare<Field> rand_mask;
                        randomShare_Helper(nP_, rgen_, rand_mask, tprand_mask, key, keySh, rand_sh);
                        TPShare<Field> tpmask_product;
                        AuthAddShare<Field> mask_product; 
                        randomShareSecret_Helper(nP_, rgen_, mask_product, tpmask_product, tp_prod, key, keySh, rand_sh_sec);
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
                        tp_ab = tpmask_in1.secret() * tpmask_in2.secret();
                        tp_ac = tpmask_in1.secret() * tpmask_in3.secret();
                        tp_bc = tpmask_in2.secret() * tpmask_in3.secret();
                        tp_abc = tpmask_in1.secret() * tpmask_in2.secret() * tpmask_in3.secret();
                        

                        TPShare<Field> tprand_mask;
                        AuthAddShare<Field> rand_mask;
                        randomShare_Helper(nP_, rgen_, rand_mask, tprand_mask, key, keySh, rand_sh);
                        

                        TPShare<Field> tpmask_ab;
                        AuthAddShare<Field> mask_ab; 
                        randomShareSecret_Helper(nP_, rgen_, mask_ab, tpmask_ab, tp_ab, key, keySh, rand_sh_sec);

                        TPShare<Field> tpmask_ac;
                        AuthAddShare<Field> mask_ac; 
                        randomShareSecret_Helper(nP_, rgen_, mask_ac, tpmask_ac, tp_ab, key, keySh, rand_sh_sec);
                        
                        TPShare<Field> tpmask_bc;
                        AuthAddShare<Field> mask_bc; 
                        randomShareSecret_Helper(nP_, rgen_, mask_bc, tpmask_bc, tp_ab, key, keySh, rand_sh_sec);
                                                
                        TPShare<Field> tpmask_abc;
                        AuthAddShare<Field> mask_abc; 
                        randomShareSecret_Helper(nP_, rgen_, mask_abc, tpmask_abc, tp_ab, key, keySh, rand_sh_sec);
                                                
                        preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult3Gate<Field>>
                                            (rand_mask, tprand_mask, 
                                            mask_ab, tpmask_ab, 
                                            mask_ac, tpmask_ac,
                                            mask_bc, tpmask_bc, 
                                            mask_abc, tpmask_abc));
                        break;
                    }

                    default: {
                        break;
                    }
                }
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


        for (const auto& level : circ_.gates_by_level) {
            for (const auto& gate : level) {
                switch (gate->type) {
                    case common::utils::GateType::kInp: {
                        auto pregate = std::make_unique<PreprocInput<Field>>();
                        auto pid = input_pid_map.at(gate->out);
                        pregate->pid = pid;
                        if (id_==pid) {
                            randomShareWithParty_Dealer(pregate->mask_value, pregate->mask, key, rand_sh_party, idx_rand_sh_party);
                        }
                        else {
                            randomShareWithParty_Party(pregate->mask, key, rand_sh_party, idx_rand_sh_party);
                        }
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
                        TPShare<Field> tprand_mask;
                        AuthAddShare<Field> rand_mask;
                        randomShare_Party(rand_mask, key, rand_sh, idx_rand_sh);
                        TPShare<Field> tpmask_product;
                        AuthAddShare<Field> mask_product; 
                        randomShareSecret_Party(mask_product, key, rand_sh_sec, idx_rand_sh_sec);
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

                        TPShare<Field> tprand_mask;
                        AuthAddShare<Field> rand_mask;
                        randomShare_Party(rand_mask, key, rand_sh, idx_rand_sh);

                        TPShare<Field> tpmask_ab;
                        AuthAddShare<Field> mask_ab; 
                        randomShareSecret_Party(mask_ab, key, rand_sh_sec, idx_rand_sh_sec);

                        TPShare<Field> tpmask_ac;
                        AuthAddShare<Field> mask_ac; 
                        randomShareSecret_Party(mask_ac, key, rand_sh_sec, idx_rand_sh_sec);
                        
                        TPShare<Field> tpmask_bc;
                        AuthAddShare<Field> mask_bc; 
                        randomShareSecret_Party(mask_bc, key, rand_sh_sec, idx_rand_sh_sec);
                                    
                        TPShare<Field> tpmask_abc;
                        AuthAddShare<Field> mask_abc; 
                        randomShareSecret_Party(mask_abc, key, rand_sh_sec, idx_rand_sh_sec);

                        preproc_.gates[gate->out] = std::move(std::make_unique<PreprocMult3Gate<Field>>
                                            (rand_mask, tprand_mask, 
                                            mask_ab, tpmask_ab, 
                                            mask_ac, tpmask_ac,
                                            mask_bc, tpmask_bc, 
                                            mask_abc, tpmask_abc));
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


        if(id_ == 0) {
            std::vector<std::vector<Field>> rand_sh(nP_);
            std::vector<std::vector<BoolRing>> b_rand_sh(nP_);
            std::vector<std::vector<Field>> rand_sh_sec(nP_);
            std::vector<std::vector<BoolRing>> b_rand_sh_sec(nP_);
            std::vector<std::vector<Field>> rand_sh_party(nP_);
            std::vector<std::vector<BoolRing>> b_rand_sh_party(nP_);

            setWireMasksHelper(input_pid_map, rand_sh, b_rand_sh, rand_sh_sec, b_rand_sh_sec,
                    rand_sh_party, b_rand_sh_party);


            for (int p=1; p<=nP_; p++) {
                size_t rand_sh_num = rand_sh[p-1].size();
                size_t b_rand_sh_num = b_rand_sh[p-1].size();
                size_t rand_sh_sec_num = rand_sh_sec[p-1].size();
                size_t b_rand_sh_sec_num = b_rand_sh_sec[p-1].size();
                size_t rand_sh_party_num = rand_sh_party[p-1].size();
                size_t b_rand_sh_party_num = b_rand_sh_party[p-1].size();
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

                network_->send(p, lengths.data(), sizeof(size_t) * 8);

                std::vector<Field> offline_arith_comm(arith_comm);
                std::vector<BoolRing> offline_bool_comm(bool_comm);
                for(size_t i = 0; i < rand_sh_num; i++) {
                    offline_arith_comm[i] = rand_sh[p-1][i];
                }
                for(size_t i = 0; i < rand_sh_sec_num; i++) {
                    offline_arith_comm[rand_sh_num + i] = rand_sh_sec[p-1][i];
                }
                for(size_t i = 0; i < rand_sh_party_num; i++) {
                    offline_arith_comm[rand_sh_sec_num + rand_sh_num + i] = rand_sh_party[p-1][i];
                }
                for(size_t i = 0; i < b_rand_sh_num; i++) {
                    offline_bool_comm[i] = b_rand_sh[p-1][i];
                }
                for(size_t i = 0; i < b_rand_sh_sec_num; i++) {
                    offline_bool_comm[b_rand_sh_num + i] = b_rand_sh_sec[p-1][i];
                }
                for(size_t i = 0; i < b_rand_sh_party_num; i++) {
                    offline_bool_comm[b_rand_sh_sec_num + b_rand_sh_num + i] = b_rand_sh_party[p-1][i];
                }
                network_->send(p, offline_arith_comm.data(), sizeof(Field) * arith_comm);
                network_->send(p, offline_bool_comm.data(), sizeof(BoolRing) * bool_comm);
            }
        }
        else {
            std::vector<Field> rand_sh;
            std::vector<BoolRing> b_rand_sh;
            std::vector<Field> rand_sh_sec;
            std::vector<BoolRing> b_rand_sh_sec;
            std::vector<Field> rand_sh_party;
            std::vector<BoolRing> b_rand_sh_party;
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
            std::vector<BoolRing> offline_bool_comm(bool_comm);

            network_->recv(0, offline_arith_comm.data(), sizeof(Field) * arith_comm);
            network_->recv(0, offline_bool_comm.data(), sizeof(BoolRing) * bool_comm);

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


};  // namespace assistedMPC
