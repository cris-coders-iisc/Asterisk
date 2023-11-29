#include "online_evaluator.h"

#include <array>

#include "../utils/helpers.h"

namespace asterisk
{
    OnlineEvaluator::OnlineEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                                     PreprocCircuit<Field> preproc,
                                     common::utils::LevelOrderedCircuit circ,
                                     int security_param, int threads, int seed)
        : nP_(nP),
          id_(id),
          security_param_(security_param),
          rgen_(id, seed),
          network_(std::move(network)),
          preproc_(std::move(preproc)),
          circ_(std::move(circ)),
          wires_(circ.num_gates),
          q_sh_(circ.num_gates),
          q_val_(circ.num_gates),
          multk_circ_(
              common::utils::Circuit<BoolRing>::generateMultK().orderGatesByLevel()),
          prefixOR_circ_(
              common::utils::Circuit<BoolRing>::generateParaPrefixOR(2).orderGatesByLevel())
    {
        tpool_ = std::make_shared<ThreadPool>(threads);
    }

    OnlineEvaluator::OnlineEvaluator(int nP, int id, std::shared_ptr<io::NetIOMP> network,
                                     PreprocCircuit<Field> preproc,
                                     common::utils::LevelOrderedCircuit circ,
                                     int security_param,
                                     std::shared_ptr<ThreadPool> tpool, int seed)
        : nP_(nP),
          id_(id),
          security_param_(security_param),
          rgen_(id, seed),
          network_(std::move(network)),
          preproc_(std::move(preproc)),
          circ_(std::move(circ)),
          tpool_(std::move(tpool)),
          wires_(circ.num_gates),
          q_sh_(circ.num_gates),
          q_val_(circ.num_gates) {}

    void OnlineEvaluator::setInputs(const std::unordered_map<common::utils::wire_t, Field> &inputs)
    {
        std::vector<Field> masked_values;

        // Input gates have depth 0
        for (auto &g : circ_.gates_by_level[0])
        {
            if (g->type == common::utils::GateType::kInp)
            {
                auto *pre_input = static_cast<PreprocInput<Field> *>(preproc_.gates[g->out].get());
                auto pid = pre_input->pid;

                if (id_ != 0)
                {
                    if (pid == id_)
                    {
                        q_val_[g->out] = pre_input->mask_value + inputs.at(g->out);
                        for (size_t i = 1; i <= nP_; i++)
                        {
                            if (i == pid)
                            {
                                wires_[g->out] = q_val_[g->out];
                                continue;
                            }
                            network_->send(i, &q_val_[g->out], sizeof(Field));
                        }
                    }
                    else
                    {
                        network_->recv(pid, &q_val_[g->out], sizeof(Field));
                        wires_[g->out] = q_val_[g->out];
                    }
                }
            }
        }
    }

    void OnlineEvaluator::setRandomInputs()
    {
        // Input gates have depth 0.
        for (auto &g : circ_.gates_by_level[0])
        {
            if (g->type == common::utils::GateType::kInp)
            {
                randomizeZZp(rgen_.all(), wires_[g->out], sizeof(Field));
            }
        }
    }

    void OnlineEvaluator::eqzEvaluate(
        const std::vector<common::utils::FIn1Gate> &eqz_gates,
        std::vector<Field> &eqz_nonTP,
        std::vector<AuthAddShare<Field>> &q_share, std::vector<Field> &masked_b)
    {

        auto num_eqz_gates = eqz_gates.size();
        std::vector<preprocg_ptr_t<BoolRing> *> vpreproc(num_eqz_gates);
        std::vector<Field> val(num_eqz_gates);

        std::vector<common::utils::wire_t> win(num_eqz_gates);
        for (size_t i = 0; i < num_eqz_gates; ++i)
        {
            auto *pre_eqz = static_cast<PreprocEqzGate<Field> *>(
                preproc_.gates[eqz_gates[i].out].get());
            vpreproc[i] = pre_eqz->multk_gates.data();
            if (id_ != 0)
            {
                val[i] = wires_[eqz_gates[i].in] + pre_eqz->padded_val;
            }
        }
        BoolEval bool_eval(id_, nP_, vpreproc, multk_circ_);
        // Set the inputs.
        for (size_t i = 0; i < num_eqz_gates; ++i)
        {
            auto val_bits = bitDecomposeTwo(val[i]);
            for (size_t j = 0; j < multk_circ_.gates_by_level[0].size(); ++j)
            {
                const auto &gate = multk_circ_.gates_by_level[0][j];

                if (gate->type == common::utils::GateType::kInp)
                {
                    bool_eval.vwires[i][gate->out] = 1 - val_bits[j];
                }
            }
        }
        bool_eval.evaluateAllLevels(*network_, *tpool_);
        auto output_shares = bool_eval.getOutputShares();

        // m_b
        std::vector<Field> output_share_val(num_eqz_gates);
        for (size_t i = 0; i < num_eqz_gates; ++i)
        {
            if (output_shares[i][0].val())
            {
                output_share_val[i] = 1;
            }
            else
            {
                output_share_val[i] = 0;
            }
        }

        // bit2A
        q_share.resize(num_eqz_gates);
        for (size_t i = 0; i < num_eqz_gates; ++i)
        {
            auto *pre_eqz = static_cast<PreprocEqzGate<Field> *>(
                preproc_.gates[eqz_gates[i].out].get());

            Field r_sum = Field(0);
            masked_b.push_back(output_share_val[i]);
            // authaddshare(q_w) = m_b * authaddshare(del_b) + authaddshare(del_w) + r_i
            if (id_ != 0)
            {
                auto del_w = pre_eqz->mask_w;
                auto del_b = pre_eqz->mask_b;

                q_share[i] = del_w - del_b * (output_share_val[i]);
                eqz_nonTP.push_back(q_share[i].valueAt());
            }
        }
    }

    void OnlineEvaluator::ltzEvaluate(
        const std::vector<common::utils::FIn1Gate> &ltz_gates,
        std::vector<Field> &ltz_nonTP,
        std::vector<AuthAddShare<Field>> &q_share, std::vector<Field> &masked_b)
    {

        auto num_ltz_gates = ltz_gates.size();
        std::vector<preprocg_ptr_t<BoolRing> *> vpreproc(num_ltz_gates);
        std::vector<Field> val(num_ltz_gates), val2(num_ltz_gates);

        // std::vector<common::utils::wire_t> win(num_ltz_gates);
        for (size_t i = 0; i < num_ltz_gates; ++i)
        {
            auto *pre_ltz = static_cast<PreprocLtzGate<Field> *>(
                preproc_.gates[ltz_gates[i].out].get());
            vpreproc[i] = pre_ltz->PrefixOR_gates.data();
            if (id_ != 0)
            {
                val[i] = wires_[ltz_gates[i].in] + pre_ltz->padded_val;
                const NTL::ZZ divisor= conv<NTL::ZZ>(2);
                ZZ M = (ZZ_p::modulus()+conv<NTL::ZZ>(1))/divisor;
                val2[i] = val[i] + conv<Field>(M);
            }
        }
        BoolEval bool_eval(id_, nP_, vpreproc, prefixOR_circ_);
        // Set the inputs.
        for (size_t i = 0; i < num_ltz_gates; ++i)
        {
            auto val_bits = bitDecomposeTwo(val[i]);            
            auto val_bits2 = bitDecomposeTwo(val2[i]);
            for (size_t j = 0; j < prefixOR_circ_.gates_by_level[0].size(); ++j)
            {                
                const auto &gate = prefixOR_circ_.gates_by_level[0][j];
                if (gate->type == common::utils::GateType::kInp)
                {
                    if (j < 64)
                    {
                        bool_eval.vwires[i][gate->out] = 1 - val_bits[63 - j];
                    }
                    else if (j < 128)
                    {
                        bool_eval.vwires[i][gate->out] = 1 - val_bits2[127 - j];
                    }
                    else if (j < 192 )
                    {
                        bool_eval.vwires[i][gate->out] = 0;
                    }
                    else 
                    {
                        bool_eval.vwires[i][gate->out] = 0;
                    }
                }
            }
        }
        bool_eval.evaluateAllLevels(*network_, *tpool_);
        auto output_shares = bool_eval.getOutputShares();

        // m_b
        std::vector<Field> output_share_val(num_ltz_gates);
        for (size_t i = 0; i < num_ltz_gates; ++i)
        {
            const NTL::ZZ divisor= conv<NTL::ZZ>(2);
            ZZ M = (ZZ_p::modulus()+conv<NTL::ZZ>(1))/divisor;
            bool val = (bool)(conv<NTL::ZZ>(val2[i]) < M);
            if (output_shares[i][0].val()^val)
            {
                output_share_val[i] = 1;
            }
            else
            {
                output_share_val[i] = 0;
            }
        }

        // bit2A
        q_share.resize(num_ltz_gates);
        for (size_t i = 0; i < num_ltz_gates; ++i)
        {
            auto *pre_ltz = static_cast<PreprocLtzGate<Field> *>(
                preproc_.gates[ltz_gates[i].out].get());

            Field r_sum = Field(0);
            masked_b.push_back(output_share_val[i]);
            // authaddshare(q_w) = m_b * authaddshare(del_b) + authaddshare(del_w) + r_i
            if (id_ != 0)
            {

                q_share[i] = pre_ltz->mask_w + pre_ltz->mask_b * (output_share_val[i]);
                ltz_nonTP.push_back(q_share[i].valueAt());
            }
        }
    }

    void OnlineEvaluator::evaluateGatesAtDepthPartySend(size_t depth,
                                                        std::vector<Field> &mult_nonTP,
                                                        std::vector<Field> &mult3_nonTP,
                                                        std::vector<Field> &mult4_nonTP,
                                                        std::vector<Field> &dotprod_nonTP)
    {

        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kMul:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                Field r_sum = Field(0);
                q_val_[g->out] = 0;

                if (id_ != 0)
                {

                    auto &m_in1 = preproc_.gates[g->in1]->mask;
                    auto &m_in2 = preproc_.gates[g->in2]->mask;
                    auto *pre_out =
                        static_cast<PreprocMultGate<Field> *>(preproc_.gates[g->out].get());
                    auto q_share = pre_out->mask + pre_out->mask_prod -
                                   m_in1 * wires_[g->in2] - m_in2 * wires_[g->in1];
                    q_share.add((wires_[g->in1] * wires_[g->in2]), id_);
                    mult_nonTP.push_back(q_share.valueAt());

                    q_sh_[g->out] = q_share;
                }

                break;
            }

            case common::utils::GateType::kMul3:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                Field r_sum = Field(0);
                q_val_[g->out] = 0;

                if (id_ != 0)
                {

                    auto &del_a = preproc_.gates[g->in1]->mask;
                    auto &del_b = preproc_.gates[g->in2]->mask;
                    auto &del_c = preproc_.gates[g->in3]->mask;

                    auto &m_a = wires_[g->in1];
                    auto &m_b = wires_[g->in2];
                    auto &m_c = wires_[g->in3];

                    auto *pre_out =
                        static_cast<PreprocMult3Gate<Field> *>(preproc_.gates[g->out].get());

                    auto q_share = pre_out->mask;

                    q_share -= pre_out->mask_abc;

                    q_share += (pre_out->mask_bc * m_a + pre_out->mask_ac * m_b + pre_out->mask_ab * m_c);

                    q_share -= (del_c * m_a * m_b + del_b * m_a * m_c + del_a * m_b * m_c);

                    q_share.add(m_a * m_b * m_c, id_);
                    mult3_nonTP.push_back(q_share.valueAt());

                    q_sh_[g->out] = q_share;
                }
                break;
            }

            case common::utils::GateType::kMul4:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                Field r_sum = Field(0);
                q_val_[g->out] = 0;

                if (id_ != 0)
                {

                    auto &del_a = preproc_.gates[g->in1]->mask;
                    auto &del_b = preproc_.gates[g->in2]->mask;
                    auto &del_c = preproc_.gates[g->in3]->mask;
                    auto &del_d = preproc_.gates[g->in4]->mask;

                    auto &m_a = wires_[g->in1];
                    auto &m_b = wires_[g->in2];
                    auto &m_c = wires_[g->in3];
                    auto &m_d = wires_[g->in4];

                    auto *pre_out =
                        static_cast<PreprocMult4Gate<Field> *>(preproc_.gates[g->out].get());

                    auto q_share = pre_out->mask;

                    q_share -= (del_d * m_a * m_b * m_c + del_c * m_a * m_b * m_d + del_b * m_a * m_c * m_d + del_a * m_b * m_c * m_d);

                    q_share += (pre_out->mask_cd * m_a * m_b + pre_out->mask_bd * m_a * m_c + pre_out->mask_bc * m_a * m_d + pre_out->mask_ad * m_b * m_c + pre_out->mask_ac * m_b * m_d + pre_out->mask_ab * m_c * m_d);

                    q_share -= (pre_out->mask_bcd * m_a + pre_out->mask_acd * m_b + pre_out->mask_abd * m_c + pre_out->mask_abc * m_d);

                    q_share += pre_out->mask_abcd;

                    q_share.add(m_a * m_b * m_c * m_d, id_);
                    mult4_nonTP.push_back(q_share.valueAt());
                    q_sh_[g->out] = q_share;
                }

                break;
            }

            case ::common::utils::GateType::kDotprod:
            {
                // All parties excluding TP sample a common random value r_in

                Field r_sum = Field(0);

                auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                auto *pre_out =
                    static_cast<PreprocDotpGate<Field> *>(preproc_.gates[g->out].get());
                if (id_ != 0)
                {

                    auto q_share = pre_out->mask + pre_out->mask_prod;
                    for (size_t i = 0; i < g->in1.size(); ++i)
                    {
                        auto win1 = g->in1[i];                    // index for masked value for left input wires
                        auto win2 = g->in2[i];                    // index for masked value for right input wires
                        auto &m_in1 = preproc_.gates[win1]->mask; // masks for left wires
                        auto &m_in2 = preproc_.gates[win2]->mask; // masks for right wires
                        q_share -= (m_in1 * wires_[win2] + m_in2 * wires_[win1]);
                        q_share.add((wires_[win1] * wires_[win2]), id_);
                    }
                    dotprod_nonTP.push_back(q_share.valueAt());
                    q_sh_[g->out] = q_share;
                }
                break;
            }
            case ::common::utils::GateType::kAdd:
            case ::common::utils::GateType::kSub:
            case ::common::utils::GateType::kConstAdd:
            case ::common::utils::GateType::kConstMul:
            {
                break;
            }

            case ::common::utils::GateType::kEqz:
            {
                break;
            }
            case ::common::utils::GateType::kLtz:
            {
                break;
            }

            default:
                break;
            }
        }
    }

    void OnlineEvaluator::evaluateGatesAtDepthPartyRecv(size_t depth,
                                                        std::vector<Field> mult_all,
                                                        std::vector<Field> mult3_all,
                                                        std::vector<Field> mult4_all,
                                                        std::vector<Field> dotprod_all,
                                                        std::vector<Field> eqz_all,
                                                        std::vector<AuthAddShare<Field>> eqz_q_share, std::vector<Field> eqz_masked_b,
                                                        std::vector<Field> ltz_all,
                                                        std::vector<AuthAddShare<Field>> ltz_q_share, std::vector<Field> ltz_masked_b)
    {
        size_t idx_mult = 0;
        size_t idx_mult3 = 0;
        size_t idx_mult4 = 0;
        size_t idx_dotprod = 0;
        size_t idx_eqz = 0;
        size_t idx_ltz = 0;

        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kAdd:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                if (id_ != 0)
                    wires_[g->out] = wires_[g->in1] + wires_[g->in2];
                q_val_[g->out] = 0;
                break;
            }

            case common::utils::GateType::kSub:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                if (id_ != 0)
                    wires_[g->out] = wires_[g->in1] - wires_[g->in2];
                q_val_[g->out] = 0;
                break;
            }

            case common::utils::GateType::kConstAdd:
            {
                auto *g = static_cast<common::utils::ConstOpGate<Field> *>(gate.get());
                wires_[g->out] = wires_[g->in] + g->cval;
                break;
            }

            case common::utils::GateType::kConstMul:
            {
                auto *g = static_cast<common::utils::ConstOpGate<Field> *>(gate.get());
                if (id_ != 0)
                    wires_[g->out] = wires_[g->in] * g->cval;
                break;
            }

            case common::utils::GateType::kMul:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = mult_all[idx_mult];
                    wires_[g->out] = q_val_[g->out];
                }
                idx_mult++;
                break;
            }
            case common::utils::GateType::kMul3:
            {
                auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = mult3_all[idx_mult3];
                    wires_[g->out] = q_val_[g->out];
                }
                idx_mult3++;
                break;
            }
            case common::utils::GateType::kMul4:
            {
                auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = mult4_all[idx_mult4];
                    wires_[g->out] = q_val_[g->out];
                }
                idx_mult4++;
                break;
            }
            case common::utils::GateType::kDotprod:
            {
                auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = dotprod_all[idx_dotprod];
                    wires_[g->out] = q_val_[g->out];
                }
                idx_dotprod++;
                break;
            }
            case common::utils::GateType::kEqz:
            {
                auto *g = static_cast<common::utils::FIn1Gate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = eqz_all[idx_eqz];
                    wires_[g->out] = q_val_[g->out];
                    wires_[g->out] = eqz_masked_b[idx_eqz] - (2 * wires_[g->out]);
                    q_sh_[g->out] = eqz_q_share[idx_eqz];
                }
                idx_eqz++;
                break;
            }
            case common::utils::GateType::kLtz:
            {
                auto *g = static_cast<common::utils::FIn1Gate *>(gate.get());
                if (id_ != 0)
                {
                    q_val_[g->out] = ltz_all[idx_ltz];
                    // m_w
                    auto m_w = q_val_[g->out];
                    // m_v
                    auto m_v = ltz_masked_b[idx_ltz] - (2 * m_w);

                    wires_[g->out] = m_v;

                    q_sh_[g->out] = ltz_q_share[idx_ltz];
                }
                idx_ltz++;
                break;
            }
            default:
                break;
            }
        }
    }

    void OnlineEvaluator::evaluateGatesAtDepth(size_t depth)
    {
        size_t mult_num = 0;
        size_t mult3_num = 0;
        size_t mult4_num = 0;
        size_t dotprod_num = 0;
        size_t eqz_num = 0;
        size_t ltz_num = 0;

        std::vector<Field> mult_nonTP;
        std::vector<Field> mult3_nonTP;
        std::vector<Field> mult4_nonTP;
        std::vector<Field> dotprod_nonTP;
        std::vector<Field> eqz_nonTP;
        std::vector<Field> ltz_nonTP;

        std::vector<Field> eqz_masked_b;
        std::vector<Field> ltz_masked_b;

        std::vector<common::utils::FIn1Gate> eqz_gates;
        std::vector<common::utils::FIn1Gate> ltz_gates;
        std::vector<AuthAddShare<Field>> eqz_q_share;
        std::vector<AuthAddShare<Field>> ltz_q_share;

        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kInp:
            case common::utils::GateType::kAdd:
            case common::utils::GateType::kSub:
            {
                break;
            }
            case common::utils::GateType::kMul:
            {
                mult_num++;
                break;
            }

            case common::utils::GateType::kMul3:
            {
                mult3_num++;
                break;
            }

            case common::utils::GateType::kMul4:
            {
                mult4_num++;
                break;
            }

            case common::utils::GateType::kDotprod:
            {
                dotprod_num++;
                break;
            }

            case ::common::utils::GateType::kEqz:
            {
                auto *g = static_cast<common::utils::FIn1Gate *>(gate.get());
                auto *pre_out =
                    static_cast<PreprocEqzGate<Field> *>(preproc_.gates[g->out].get());
                eqz_gates.push_back(*g);
                eqz_num++;
                break;
            }
            case ::common::utils::GateType::kLtz:
            {
                auto *g = static_cast<common::utils::FIn1Gate *>(gate.get());
                ltz_gates.push_back(*g);
                ltz_num++;
                break;
            }
            }
        }

        size_t total_comm = mult_num + mult3_num +
                            mult4_num + dotprod_num +
                            eqz_num + ltz_num;
        if (eqz_num > 0)
        {
            eqzEvaluate(eqz_gates, eqz_nonTP, eqz_q_share, eqz_masked_b);
        }
        if (ltz_num > 0)
        {
            ltzEvaluate(ltz_gates, ltz_nonTP, ltz_q_share, ltz_masked_b);
        }

        if (id_ != 0)
        {
            evaluateGatesAtDepthPartySend(depth, mult_nonTP, mult3_nonTP, mult4_nonTP, dotprod_nonTP);

            std::vector<Field> online_comm_to_TP(total_comm);

            for (size_t i = 0; i < mult_num; i++)
            {
                online_comm_to_TP[i] = mult_nonTP[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                online_comm_to_TP[i + mult_num] = mult3_nonTP[i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num] = mult4_nonTP[i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num + mult4_num] = dotprod_nonTP[i];
            }
            for (size_t i = 0; i < eqz_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num + mult4_num +
                                  dotprod_num] = eqz_nonTP[i];
            }
            for (size_t i = 0; i < ltz_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num + mult4_num +
                                  dotprod_num + eqz_num] = ltz_nonTP[i];
            }

            size_t per_party_comm = floor(total_comm / nP_);
            size_t last_party_comm = per_party_comm + (total_comm % nP_);

            for (size_t pid = 1; pid <= nP_; pid++)
            {
                if (id_ == pid)
                {
                    continue;
                }
                if (pid != nP_)
                {
                    std::vector<Field> online_comm_to_party(per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        online_comm_to_party[i] = online_comm_to_TP[(pid - 1) * per_party_comm + i];
                    }
                    network_->send(pid, online_comm_to_party.data(), sizeof(Field) * per_party_comm);
                }
                else
                {
                    std::vector<Field> online_comm_to_party(last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        online_comm_to_party[i] = online_comm_to_TP[(pid - 1) * per_party_comm + i];
                    }
                    network_->send(pid, online_comm_to_party.data(), sizeof(Field) * last_party_comm);
                }
            }

            std::vector<Field> agg_values_send(per_party_comm, Field(0));
            std::vector<Field> agg_values_send_last(last_party_comm, Field(0));
            for (size_t pid = 1; pid <= nP_; pid++)
            {
                if (id_ == pid)
                {
                    if (id_ != nP_)
                    {
                        for (size_t i = 0; i < per_party_comm; i++)
                        {
                            agg_values_send[i] += online_comm_to_TP[(pid - 1) * per_party_comm + i];
                        }
                    }
                    else
                    {
                        for (size_t i = 0; i < last_party_comm; i++)
                        {
                            agg_values_send_last[i] += online_comm_to_TP[(pid - 1) * per_party_comm + i];
                        }
                    }
                    continue;
                }
                if (id_ != nP_)
                {
                    std::vector<Field> online_comm_to_party_recv(per_party_comm);
                    network_->recv(pid, online_comm_to_party_recv.data(), sizeof(Field) * per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        agg_values_send[i] += online_comm_to_party_recv[i];
                    }
                }
                else
                {
                    std::vector<Field> online_comm_to_party_recv(last_party_comm);
                    network_->recv(pid, online_comm_to_party_recv.data(), sizeof(Field) * last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        agg_values_send_last[i] += online_comm_to_party_recv[i];
                    }
                }
            }

            for (size_t pid = 1; pid <= nP_; pid++)
            {
                if (id_ == pid)
                {
                    continue;
                }
                if (id_ != nP_)
                {
                    network_->send(pid, agg_values_send.data(), sizeof(Field) * per_party_comm);
                }
                else
                {
                    network_->send(pid, agg_values_send_last.data(), sizeof(Field) * last_party_comm);
                }
            }

            std::vector<Field> agg_values(total_comm, Field(0));
            for (size_t pid = 1; pid <= nP_; pid++)
            {
                if (id_ == pid)
                {
                    if (id_ != nP_)
                    {
                        for (size_t i = 0; i < per_party_comm; i++)
                        {
                            agg_values[(pid - 1) * per_party_comm + i] += agg_values_send[i];
                        }
                    }
                    else
                    {
                        for (size_t i = 0; i < last_party_comm; i++)
                        {
                            agg_values[(pid - 1) * per_party_comm + i] += agg_values_send_last[i];
                        }
                    }
                    continue;
                }
                if (pid != nP_)
                {
                    std::vector<Field> agg_values_recv(per_party_comm);
                    network_->recv(pid, agg_values_recv.data(), sizeof(Field) * per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        agg_values[(pid - 1) * per_party_comm + i] += agg_values_recv[i];
                    }
                }
                else
                {
                    std::vector<Field> agg_values_recv(last_party_comm);
                    network_->recv(pid, agg_values_recv.data(), sizeof(Field) * last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        agg_values[(pid - 1) * per_party_comm + i] += agg_values_recv[i];
                    }
                }
            }

            std::vector<Field> mult_all(mult_num);
            std::vector<Field> mult3_all(mult3_num);
            std::vector<Field> mult4_all(mult4_num);
            std::vector<Field> dotprod_all(dotprod_num);
            std::vector<Field> eqz_all(eqz_num);
            std::vector<Field> ltz_all(ltz_num);

            for (size_t i = 0; i < mult_num; i++)
            {
                mult_all[i] = agg_values[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                mult3_all[i] = agg_values[mult_num + i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                mult4_all[i] = agg_values[mult3_num + mult_num + i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                dotprod_all[i] = agg_values[mult4_num +
                                            mult3_num +
                                            mult_num + i];
            }
            for (size_t i = 0; i < eqz_num; i++)
            {
                eqz_all[i] = agg_values[dotprod_num +
                                        mult4_num +
                                        mult3_num +
                                        mult_num + i];
            }
            for (size_t i = 0; i < ltz_num; i++)
            {
                ltz_all[i] = agg_values[eqz_num +
                                        dotprod_num +
                                        mult4_num +
                                        mult3_num +
                                        mult_num + i];
            }
            evaluateGatesAtDepthPartyRecv(depth,
                                          mult_all,
                                          mult3_all,
                                          mult4_all,
                                          dotprod_all,
                                          eqz_all, eqz_q_share, eqz_masked_b,
                                          ltz_all, ltz_q_share, ltz_masked_b);
        }
    }

    bool OnlineEvaluator::MACVerification()
    {
        emp::block cc_key[2];
        if (id_ == 0)
        {
            rgen_.self().random_block(cc_key, 2);
            for (int i = 1; i <= nP_; i++)
            {
                network_->send(i, cc_key, 2 * sizeof(emp::block));
            }
        }
        else
        {
            network_->recv(0, cc_key, 2 * sizeof(emp::block));
        }
        emp::PRG prg;
        prg.reseed(cc_key);
        Field res = Field(0);
        if (id_ != 0)
        {
            Field key = preproc_.gates[0]->mask.keySh();
            int m = circ_.num_gates;
            Field omega = Field(0);
            std::unordered_map<common::utils::wire_t, Field> rho;

            for (size_t i = 0; i < circ_.gates_by_level.size(); ++i)
            {
                for (auto &gate : circ_.gates_by_level[i])
                {
                    switch (gate->type)
                    {
                    case common::utils::GateType::kMul:
                    {
                        auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                        randomizeZZp(prg, rho[g->out], sizeof(Field));
                        omega += rho[g->out] * (q_val_[g->out] * key - q_sh_[g->out].tagAt());
                    }
                    case common::utils::GateType::kDotprod:
                    {
                        auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                        randomizeZZp(prg, rho[g->out], sizeof(Field));
                        omega += rho[g->out] * (q_val_[g->out] * key - q_sh_[g->out].tagAt());
                    }
                    case common::utils::GateType::kMul3:
                    {
                        auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                        randomizeZZp(prg, rho[g->out], sizeof(Field));
                        omega += rho[g->out] * (q_val_[g->out] * key - q_sh_[g->out].tagAt());
                    }
                    case common::utils::GateType::kMul4:
                    {
                        auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                        randomizeZZp(prg, rho[g->out], sizeof(Field));
                        omega += rho[g->out] * (q_val_[g->out] * key - q_sh_[g->out].tagAt());
                    }
                    case common::utils::GateType::kConstAdd:
                    case common::utils::GateType::kConstMul:
                    case common::utils::GateType::kAdd:
                    case common::utils::GateType::kSub:
                    {
                        break;
                    }
                    }
                }
            }
            network_->send(0, &omega, sizeof(Field));
        }
        else
        {
            Field omega;

            for (int i = 1; i <= nP_; i++)
            {
                network_->recv(i, &omega, sizeof(Field));
                res += omega;
            }

            for (int i = 1; i <= nP_; i++)
            {
                network_->send(i, &res, sizeof(Field));
            }
        }
        if (id_ != 0)
        {
            network_->recv(0, &res, sizeof(Field));
        }

        if (res == 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    std::vector<Field> OnlineEvaluator::getOutputs()
    {
        std::vector<Field> outvals(circ_.outputs.size());
        if (circ_.outputs.empty())
        {
            return outvals;
        }

        if (id_ == 0)
        {
            std::vector<Field> output_masks(circ_.outputs.size());
            for (size_t i = 0; i < circ_.outputs.size(); ++i)
            {
                auto wout = circ_.outputs[i];
                Field outmask = preproc_.gates[wout]->tpmask.secret();
                output_masks[i] = outmask;
            }
            for (int i = 1; i <= nP_; ++i)
            {
                network_->send(i, output_masks.data(), output_masks.size() * sizeof(Field));
            }
            return outvals;
        }
        else
        {
            std::vector<Field> output_masks(circ_.outputs.size());
            network_->recv(0, output_masks.data(), output_masks.size() * sizeof(Field));
            for (size_t i = 0; i < circ_.outputs.size(); ++i)
            {
                Field outmask = output_masks[i];
                auto wout = circ_.outputs[i];
                outvals[i] = wires_[wout] - outmask;
            }
            return outvals;
        }
    }

    Field OnlineEvaluator::reconstruct(AuthAddShare<Field> &shares)
    {
        Field reconstructed_value = Field(0);
        if (id_ != 0)
        {
            network_->send(0, &shares.valueAt(), sizeof(Field));
        }
        else if (id_ == 0)
        {

            for (size_t i = 1; i <= nP_; ++i)
            {
                std::vector<Field> share_val;
                network_->recv(i, &share_val[i], sizeof(Field));
                reconstructed_value += share_val[i];
            }
        }
        return reconstructed_value;
    }

    std::vector<Field> OnlineEvaluator::evaluateCircuit(const std::unordered_map<common::utils::wire_t, Field> &inputs)
    {
        setInputs(inputs);

        for (size_t i = 0; i < circ_.gates_by_level.size(); ++i)
        {
            evaluateGatesAtDepth(i);
        }

        if (MACVerification())
        {
            return getOutputs();
        }
        else
        {
            std::cout << "Malicious Activity Detected!!!" << std::endl;
            std::vector<Field> abort(circ_.outputs.size(), Field(0));
            return abort;
        }
    }

    // Methods for evaluating boolean circuits
    BoolEvaluator::BoolEvaluator(int nP, int id,
                                 std::shared_ptr<io::NetIOMP> network,
                                 PreprocCircuit<BoolRing> preproc,
                                 common::utils::LevelOrderedCircuit circ,
                                 int seed)
        : nP_(nP),
          id_(id),
          rgen_(id, seed),
          network_(std::move(network)),
          preproc_(std::move(preproc)),
          circ_(std::move(circ)),
          wires_(circ.num_gates),
          q_sh_(circ.num_gates),
          q_val_(circ.num_gates) {}

    void BoolEvaluator::setInputs(
        const std::unordered_map<common::utils::wire_t, BoolRing> &inputs)
    {
        // Input gates have depth 0.
        std::vector<BoolRing> masked_values;
        std::vector<size_t> num_inp_pid(nP_, 0);

        // Input gates have depth 0
        for (auto &g : circ_.gates_by_level[0])
        {
            if (g->type == common::utils::GateType::kInp)
            {
                auto *pre_input = static_cast<PreprocInput<BoolRing> *>(preproc_.gates[g->out].get());
                auto pid = pre_input->pid;

                num_inp_pid[pid]++;
                BoolRing r_in;
                // All parties excluding TP sample a common random value r_in
                if (id_ != 0)
                {
                    uint8_t tmp;
                    rgen_.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                    r_in = tmp % 2;
                    if (pid == id_)
                    {
                        // pre_input->pid computes pre_input->mask + inputs.at(g->out) + r_in
                        q_val_[g->out] = pre_input->mask_value + inputs.at(g->out) + r_in;
                        network_->send(0, &q_val_[g->out], sizeof(BoolRing));
                    }
                }
                else if (id_ == 0)
                {
                    network_->recv(pid, &q_val_[g->out], sizeof(BoolRing));
                    for (int i = 1; i <= nP_; i++)
                    {
                        network_->send(i, &q_val_[g->out], sizeof(BoolRing));
                    }
                }
                if (id_ != 0)
                {
                    network_->recv(0, &q_val_[g->out], sizeof(BoolRing));
                    wires_[g->out] = q_val_[g->out] - r_in;
                }
            }
        }
    }

    void BoolEvaluator::setRandomInputs()
    {
        // Input gates have depth 0.
        for (auto &g : circ_.gates_by_level[0])
        {
            if (g->type == common::utils::GateType::kInp)
            {
                uint8_t tmp;
                rgen_.all().random_data(&tmp, sizeof(BoolRing));
                wires_[g->out] = tmp % 2;
            }
        }
    }

    void BoolEvaluator::evaluateGatesAtDepthPartySend(size_t depth,
                                                      std::vector<BoolRing> &mult_nonTP, std::vector<BoolRing> &r_mult_pad,
                                                      std::vector<BoolRing> &mult3_nonTP, std::vector<BoolRing> &r_mult3_pad,
                                                      std::vector<BoolRing> &mult4_nonTP, std::vector<BoolRing> &r_mult4_pad,
                                                      std::vector<BoolRing> &dotprod_nonTP, std::vector<BoolRing> &r_dotprod_pad)
    {
        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kMul:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                BoolRing r_sum(0);
                q_val_[g->out] = 0;

                if (id_ != 0)
                {
                    std::vector<BoolRing> r_mul(nP_);
                    for (int i = 0; i < nP_; i++)
                    {
                        uint8_t tmp;
                        rgen_.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                        r_mul[i] = tmp % 2;
                        r_sum += r_mul[i];
                    }

                    r_mult_pad.push_back(r_sum);

                    auto &m_in1 = preproc_.gates[g->in1]->mask;
                    auto &m_in2 = preproc_.gates[g->in2]->mask;
                    auto *pre_out =
                        static_cast<PreprocMultGate<BoolRing> *>(preproc_.gates[g->out].get());
                    auto q_share = pre_out->mask + pre_out->mask_prod -
                                   m_in1 * wires_[g->in2] - m_in2 * wires_[g->in1];
                    q_share.add((wires_[g->in1] * wires_[g->in2]), id_);
                    for (int i = 1; i <= nP_; i++)
                    {
                        q_share.addWithAdder(r_mul[id_ - 1], id_, i);
                    }
                    mult_nonTP.push_back(q_share.valueAt());

                    q_sh_[g->out] = q_share;
                }

                break;
            }

            case common::utils::GateType::kMul3:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                BoolRing r_sum(0);
                q_val_[g->out] = 0;

                if (id_ != 0)
                {
                    std::vector<BoolRing> r_mul3(nP_);
                    for (int i = 0; i < nP_; i++)
                    {
                        uint8_t tmp;
                        rgen_.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                        r_mul3[i] = tmp % 2;
                        r_sum += r_mul3[i];
                    }
                    r_mult3_pad.push_back(r_sum);

                    auto &del_a = preproc_.gates[g->in1]->mask;
                    auto &del_b = preproc_.gates[g->in2]->mask;
                    auto &del_c = preproc_.gates[g->in3]->mask;

                    auto &m_a = wires_[g->in1];
                    auto &m_b = wires_[g->in2];
                    auto &m_c = wires_[g->in3];

                    auto *pre_out =
                        static_cast<PreprocMult3Gate<BoolRing> *>(preproc_.gates[g->out].get());

                    auto q_share = pre_out->mask;

                    q_share -= pre_out->mask_abc;

                    q_share += (pre_out->mask_bc * m_a + pre_out->mask_ac * m_b + pre_out->mask_ab * m_c);

                    q_share -= (del_c * m_a * m_b + del_b * m_a * m_c + del_a * m_b * m_c);

                    q_share.add(m_a * m_b * m_c, id_);
                    for (int i = 1; i <= nP_; i++)
                    {
                        q_share.addWithAdder(r_mul3[id_ - 1], id_, i);
                    }
                    mult3_nonTP.push_back(q_share.valueAt());

                    q_sh_[g->out] = q_share;
                }
                break;
            }

            case common::utils::GateType::kMul4:
            {
                // All parties excluding TP sample a common random value r_in
                auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                BoolRing r_sum = 0;
                q_val_[g->out] = 0;

                if (id_ != 0)
                {
                    std::vector<BoolRing> r_mul4(nP_);
                    for (int i = 0; i < nP_; i++)
                    {
                        uint8_t tmp;
                        rgen_.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                        r_mul4[i] = tmp;
                        r_sum += r_mul4[i];
                    }

                    r_mult4_pad.push_back(r_sum);

                    auto &del_a = preproc_.gates[g->in1]->mask;
                    auto &del_b = preproc_.gates[g->in2]->mask;
                    auto &del_c = preproc_.gates[g->in3]->mask;
                    auto &del_d = preproc_.gates[g->in4]->mask;

                    auto &m_a = wires_[g->in1];
                    auto &m_b = wires_[g->in2];
                    auto &m_c = wires_[g->in3];
                    auto &m_d = wires_[g->in4];

                    auto *pre_out =
                        static_cast<PreprocMult4Gate<BoolRing> *>(preproc_.gates[g->out].get());

                    auto q_share = pre_out->mask;

                    q_share -= (del_d * m_a * m_b * m_c + del_c * m_a * m_b * m_d + del_b * m_a * m_c * m_d + del_a * m_b * m_c * m_d);

                    q_share += (pre_out->mask_cd * m_a * m_b + pre_out->mask_bd * m_a * m_c + pre_out->mask_bc * m_a * m_d + pre_out->mask_ad * m_b * m_c + pre_out->mask_ac * m_b * m_d + pre_out->mask_ab * m_c * m_d);

                    q_share -= (pre_out->mask_bcd * m_a + pre_out->mask_acd * m_b + pre_out->mask_abd * m_c + pre_out->mask_abc * m_d);

                    q_share += pre_out->mask_abcd;

                    q_share.add(m_a * m_b * m_c * m_d, id_);
                    for (int i = 1; i <= nP_; i++)
                    {
                        q_share.addWithAdder(r_mul4[id_ - 1], id_, i);
                    }
                    mult4_nonTP.push_back(q_share.valueAt());

                    q_sh_[g->out] = q_share;
                }

                break;
            }

            case ::common::utils::GateType::kDotprod:
            {
                // All parties excluding TP sample a common random value r_in

                BoolRing r_sum = 0;

                auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                auto *pre_out =
                    static_cast<PreprocDotpGate<BoolRing> *>(preproc_.gates[g->out].get());
                if (id_ != 0)
                {
                    std::vector<BoolRing> r_dotp(nP_);
                    for (int i = 0; i < nP_; i++)
                    {
                        uint8_t tmp;
                        rgen_.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                        r_dotp[i] = tmp % 2;
                        r_sum += r_dotp[i];
                    }

                    r_dotprod_pad.push_back(r_sum);

                    auto q_share = pre_out->mask + pre_out->mask_prod;
                    for (size_t i = 0; i < g->in1.size(); ++i)
                    {
                        auto win1 = g->in1[i];                    // index for masked value for left input wires
                        auto win2 = g->in2[i];                    // index for masked value for right input wires
                        auto &m_in1 = preproc_.gates[win1]->mask; // masks for left wires
                        auto &m_in2 = preproc_.gates[win2]->mask; // masks for right wires
                        q_share -= (m_in1 * wires_[win2] + m_in2 * wires_[win1]);
                        q_share.add((wires_[win1] * wires_[win2]), id_);
                    }
                    for (int i = 1; i <= nP_; i++)
                    {
                        q_share.addWithAdder(r_dotp[id_ - 1], id_, i);
                    }
                    dotprod_nonTP.push_back(q_share.valueAt());
                    q_sh_[g->out] = q_share;
                }
                break;
            }
            default:
                break;
            }
        }
    }
    void BoolEvaluator::evaluateGatesAtDepthPartyRecv(size_t depth,
                                                      std::vector<BoolRing> mult_all, std::vector<BoolRing> r_mult_pad,
                                                      std::vector<BoolRing> mult3_all, std::vector<BoolRing> r_mult3_pad,
                                                      std::vector<BoolRing> mult4_all, std::vector<BoolRing> r_mult4_pad,
                                                      std::vector<BoolRing> dotprod_all, std::vector<BoolRing> r_dotprod_pad)
    {
        size_t idx_mult = 0;
        size_t idx_mult3 = 0;
        size_t idx_mult4 = 0;
        size_t idx_dotprod = 0;
        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kAdd:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                if (id_ != 0)
                    wires_[g->out] = wires_[g->in1] + wires_[g->in2];
                q_val_[g->out] = 0;
                break;
            }

            case common::utils::GateType::kSub:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                if (id_ != 0)
                    wires_[g->out] = wires_[g->in1] - wires_[g->in2];
                q_val_[g->out] = 0;
                break;
            }

            case common::utils::GateType::kConstAdd:
            {
                auto *g = static_cast<common::utils::ConstOpGate<BoolRing> *>(gate.get());
                wires_[g->out] = wires_[g->in] + g->cval;
                break;
            }

            case common::utils::GateType::kConstMul:
            {
                auto *g = static_cast<common::utils::ConstOpGate<BoolRing> *>(gate.get());
                wires_[g->out] = wires_[g->in] * g->cval;
                break;
            }

            case common::utils::GateType::kMul:
            {
                auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                q_val_[g->out] = mult_all[idx_mult];
                wires_[g->out] = q_val_[g->out] - r_mult_pad[idx_mult];
                idx_mult++;
                break;
            }
            case common::utils::GateType::kMul3:
            {
                auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                q_val_[g->out] = mult3_all[idx_mult3];
                wires_[g->out] = q_val_[g->out] - r_mult3_pad[idx_mult3];
                idx_mult3++;
                break;
            }
            case common::utils::GateType::kMul4:
            {
                auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                q_val_[g->out] = mult4_all[idx_mult4];
                wires_[g->out] = q_val_[g->out] - r_mult4_pad[idx_mult4];
                idx_mult4++;
                break;
            }
            case common::utils::GateType::kDotprod:
            {
                auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                q_val_[g->out] = dotprod_all[idx_dotprod];
                wires_[g->out] = q_val_[g->out] - r_dotprod_pad[idx_dotprod];
                idx_dotprod++;
                break;
            }
            default:
                break;
            }
        }
    }

    void BoolEvaluator::evaluateGatesAtDepth(size_t depth)
    {

        size_t mult_num = 0;
        size_t mult3_num = 0;
        size_t mult4_num = 0;
        size_t dotprod_num = 0;

        for (auto &gate : circ_.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kMul:
            {
                mult_num++;
                break;
            }

            case common::utils::GateType::kMul3:
            {
                mult3_num++;
                break;
            }

            case common::utils::GateType::kMul4:
            {
                mult4_num++;
                break;
            }

            case common::utils::GateType::kDotprod:
            {
                dotprod_num++;
                break;
            }
            }
        }

        size_t total_comm = mult_num + mult3_num + mult4_num + dotprod_num;

        std::vector<BoolRing> mult_nonTP;
        std::vector<BoolRing> mult3_nonTP;
        std::vector<BoolRing> mult4_nonTP;
        std::vector<BoolRing> dotprod_nonTP;

        std::vector<BoolRing> r_mult_pad;
        std::vector<BoolRing> r_mult3_pad;
        std::vector<BoolRing> r_mult4_pad;
        std::vector<BoolRing> r_dotprod_pad;

        if (id_ != 0)
        {
            evaluateGatesAtDepthPartySend(depth,
                                          mult_nonTP, r_mult_pad,
                                          mult3_nonTP, r_mult3_pad,
                                          mult4_nonTP, r_mult4_pad,
                                          dotprod_nonTP, r_dotprod_pad);

            std::vector<BoolRing> online_comm_to_TP(total_comm);

            for (size_t i = 0; i < mult_num; i++)
            {
                online_comm_to_TP[i] = mult_nonTP[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                online_comm_to_TP[i + mult_num] = mult3_nonTP[i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num] = mult4_nonTP[i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num + mult4_num] = dotprod_nonTP[i];
            }

            auto net_data = BoolRing::pack(online_comm_to_TP.data(), total_comm);
            network_->send(0, net_data.data(), sizeof(uint8_t) * net_data.size());
        }
        else if (id_ == 0)
        {
            size_t nbytes = (total_comm + 7) / 8;
            std::vector<uint8_t> net_data(nbytes);
            // std::vector<BoolRing> online_comm_to_TP(total_comm, 0);
            std::vector<BoolRing> agg_values(total_comm, 0);

            for (int pid = 1; pid <= nP_; pid++)
            {
                network_->recv(pid, net_data.data(), nbytes * sizeof(uint8_t));
                // network_->recv(pid, online_comm_to_TP.data(), sizeof(BoolRing) * total_comm);
                auto online_comm_to_TP = BoolRing::unpack(net_data.data(), total_comm);
                for (int i = 0; i < total_comm; i++)
                {

                    agg_values[i] += online_comm_to_TP[i];
                }
            }

            net_data = BoolRing::pack(agg_values.data(), total_comm);
            for (int pid = 1; pid <= nP_; pid++)
            {
                network_->send(pid, net_data.data(), nbytes);
            }
        }

        if (id_ != 0)
        {
            size_t nbytes = (total_comm + 7) / 8;
            std::vector<uint8_t> net_data(nbytes);
            network_->recv(0, net_data.data(), nbytes);
            auto agg_values = BoolRing::unpack(net_data.data(), total_comm);

            std::vector<BoolRing> mult_all(mult_num);
            std::vector<BoolRing> mult3_all(mult3_num);
            std::vector<BoolRing> mult4_all(mult4_num);
            std::vector<BoolRing> dotprod_all(dotprod_num);

            for (size_t i = 0; i < mult_num; i++)
            {
                mult_all[i] = agg_values[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                mult3_all[i] = agg_values[mult_num + i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                mult4_all[i] = agg_values[mult3_num + mult_num + i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                dotprod_all[i] = agg_values[mult4_num +
                                            mult3_num +
                                            mult_num + i];
            }
            evaluateGatesAtDepthPartyRecv(depth,
                                          mult_all, r_mult_pad,
                                          mult3_all, r_mult3_pad,
                                          mult4_all, r_mult4_pad,
                                          dotprod_all, r_dotprod_pad);
        }
    }
    void BoolEvaluator::evaluateAllLevels()
    {
        for (size_t i = 0; i < circ_.gates_by_level.size(); ++i)
        {
            evaluateGatesAtDepth(i);
        }
    }

    std::vector<BoolRing> BoolEvaluator::getOutputs()
    {
        // if id_ == 0 : send preproc_.gates[wout]->mask
        // if id_ != 1 : receive the above value and compute masked_value + mask
        std::vector<BoolRing> outvals(circ_.outputs.size());
        if (circ_.outputs.empty())
        {
            return outvals;
        }

        if (id_ == 0)
        {
            std::vector<BoolRing> output_masks(circ_.outputs.size());
            for (size_t i = 0; i < circ_.outputs.size(); ++i)
            {
                auto wout = circ_.outputs[i];
                BoolRing outmask = preproc_.gates[wout]->tpmask.secret();
                output_masks[i] = outmask;
            }
            for (int i = 1; i <= nP_; ++i)
            {
                network_->send(i, output_masks.data(), output_masks.size() * sizeof(BoolRing));
            }
            return outvals;
        }
        else
        {
            std::vector<BoolRing> output_masks(circ_.outputs.size());
            network_->recv(0, output_masks.data(), output_masks.size() * sizeof(BoolRing));
            for (size_t i = 0; i < circ_.outputs.size(); ++i)
            {
                BoolRing outmask = output_masks[i];
                auto wout = circ_.outputs[i];
                outvals[i] = wires_[wout] - outmask;
            }
            return outvals;
        }
    }

    std::vector<BoolRing> BoolEvaluator::evaluateCircuit(const std::unordered_map<common::utils::wire_t, BoolRing> &inputs)
    {
        setInputs(inputs);

        for (size_t i = 0; i < circ_.gates_by_level.size(); ++i)
        {
            evaluateGatesAtDepth(i);
        }
        return getOutputs();

        // if(MACVerification()) { return getOutputs(); }
        // else {
        //     std::cout<< "Malicious Activity Detected!!!" << std::endl;
        //     std::vector<Field> abort (circ_.outputs.size(), 0);
        //     return abort;
        //     }
    }

    BoolEval::BoolEval(int my_id, int nP,
                       std::vector<preprocg_ptr_t<BoolRing> *> vpreproc,
                       common::utils::LevelOrderedCircuit circ, int seed)
        : id(my_id),
          nP(nP),
          rgen(id, seed),
          vwires(vpreproc.size(), std::vector<BoolRing>(circ.num_gates)),
          vqval(vpreproc.size(), std::vector<BoolRing>(circ.num_gates)),
          vqsh(vpreproc.size(), std::vector<AuthAddShare<BoolRing>>(circ.num_gates)),
          vpreproc(std::move(vpreproc)),
          circ(std::move(circ)) {}

    void BoolEval::evaluateGatesAtDepthPartySend(size_t depth,
                                                 std::vector<BoolRing> &mult_nonTP, std::vector<BoolRing> &r_mult_pad,
                                                 std::vector<BoolRing> &mult3_nonTP, std::vector<BoolRing> &r_mult3_pad,
                                                 std::vector<BoolRing> &mult4_nonTP, std::vector<BoolRing> &r_mult4_pad,
                                                 std::vector<BoolRing> &dotprod_nonTP, std::vector<BoolRing> &r_dotprod_pad, ThreadPool &tpool)
    {

        for (size_t i = 0; i < vwires.size(); ++i)
        {
            const auto &preproc = vpreproc[i];
            auto &wires = vwires[i];
            auto &qval = vqval[i];
            auto &qsh = vqsh[i];

            for (auto &gate : circ.gates_by_level[depth])
            {
                switch (gate->type)
                {
                case common::utils::GateType::kMul:
                {
                    // All parties excluding TP sample a common random value r_in
                    auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                    BoolRing r_sum(0);
                    qval[g->out] = 0;

                    if (id != 0)
                    {
                        std::vector<BoolRing> r_mul(nP);
                        for (int i = 0; i < nP; i++)
                        {
                            uint8_t tmp;
                            rgen.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                            r_mul[i] = tmp % 2;
                            r_sum += r_mul[i];
                        }

                        r_mult_pad.push_back(r_sum);

                        auto &m_in1 = preproc[g->in1]->mask;
                        auto &m_in2 = preproc[g->in2]->mask;
                        auto *pre_out =
                            static_cast<PreprocMultGate<BoolRing> *>(preproc[g->out].get());
                        auto q_share = pre_out->mask + pre_out->mask_prod -
                                       m_in1 * wires[g->in2] - m_in2 * wires[g->in1];
                        q_share.add((wires[g->in1] * wires[g->in2]), id);
                        for (int i = 1; i <= nP; i++)
                        {
                            q_share.addWithAdder(r_mul[id - 1], id, i);
                        }
                        mult_nonTP.push_back(q_share.valueAt());

                        qsh[g->out] = q_share;
                    }

                    break;
                }

                case common::utils::GateType::kMul3:
                {
                    // All parties excluding TP sample a common random value r_in
                    auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                    BoolRing r_sum(0);
                    qval[g->out] = 0;

                    if (id != 0)
                    {
                        std::vector<BoolRing> r_mul3(nP);
                        for (int i = 0; i < nP; i++)
                        {
                            uint8_t tmp;
                            rgen.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                            r_mul3[i] = tmp % 2;
                            r_sum += r_mul3[i];
                        }
                        r_mult3_pad.push_back(r_sum);

                        auto &del_a = preproc[g->in1]->mask;
                        auto &del_b = preproc[g->in2]->mask;
                        auto &del_c = preproc[g->in3]->mask;

                        auto &m_a = wires[g->in1];
                        auto &m_b = wires[g->in2];
                        auto &m_c = wires[g->in3];

                        auto *pre_out =
                            static_cast<PreprocMult3Gate<BoolRing> *>(preproc[g->out].get());

                        auto q_share = pre_out->mask;

                        q_share -= pre_out->mask_abc;

                        q_share += (pre_out->mask_bc * m_a + pre_out->mask_ac * m_b + pre_out->mask_ab * m_c);

                        q_share -= (del_c * m_a * m_b + del_b * m_a * m_c + del_a * m_b * m_c);

                        q_share.add(m_a * m_b * m_c, id);
                        for (int i = 1; i <= nP; i++)
                        {
                            q_share.addWithAdder(r_mul3[id - 1], id, i);
                        }
                        mult3_nonTP.push_back(q_share.valueAt());

                        qsh[g->out] = q_share;
                    }
                    break;
                }

                case common::utils::GateType::kMul4:
                {
                    // All parties excluding TP sample a common random value r_in
                    auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                    BoolRing r_sum = 0;
                    qval[g->out] = 0;

                    if (id != 0)
                    {
                        std::vector<BoolRing> r_mul4(nP);
                        for (int i = 0; i < nP; i++)
                        {
                            uint8_t tmp;
                            rgen.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                            r_mul4[i] = tmp % 2;
                            r_sum += r_mul4[i];
                        }

                        r_mult4_pad.push_back(r_sum);

                        auto &del_a = preproc[g->in1]->mask;
                        auto &del_b = preproc[g->in2]->mask;
                        auto &del_c = preproc[g->in3]->mask;
                        auto &del_d = preproc[g->in4]->mask;

                        auto &m_a = wires[g->in1];
                        auto &m_b = wires[g->in2];
                        auto &m_c = wires[g->in3];
                        auto &m_d = wires[g->in4];

                        auto *pre_out =
                            static_cast<PreprocMult4Gate<BoolRing> *>(preproc[g->out].get());

                        auto q_share = pre_out->mask;

                        q_share -= (del_d * m_a * m_b * m_c + del_c * m_a * m_b * m_d + del_b * m_a * m_c * m_d + del_a * m_b * m_c * m_d);

                        q_share += (pre_out->mask_cd * m_a * m_b + pre_out->mask_bd * m_a * m_c + pre_out->mask_bc * m_a * m_d + pre_out->mask_ad * m_b * m_c + pre_out->mask_ac * m_b * m_d + pre_out->mask_ab * m_c * m_d);

                        q_share -= (pre_out->mask_bcd * m_a + pre_out->mask_acd * m_b + pre_out->mask_abd * m_c + pre_out->mask_abc * m_d);

                        q_share += pre_out->mask_abcd;

                        q_share.add(m_a * m_b * m_c * m_d, id);
                        for (int i = 1; i <= nP; i++)
                        {
                            q_share.addWithAdder(r_mul4[id - 1], id, i);
                        }
                        mult4_nonTP.push_back(q_share.valueAt());

                        qsh[g->out] = q_share;
                    }

                    break;
                }

                case ::common::utils::GateType::kDotprod:
                {
                    // All parties excluding TP sample a common random value r_in

                    BoolRing r_sum = 0;

                    auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                    auto *pre_out =
                        static_cast<PreprocDotpGate<BoolRing> *>(preproc[g->out].get());
                    if (id != 0)
                    {
                        std::vector<BoolRing> r_dotp(nP);
                        for (int i = 0; i < nP; i++)
                        {
                            uint8_t tmp;
                            rgen.all_minus_0().random_data(&tmp, sizeof(BoolRing));
                            r_dotp[i] = tmp % 2;
                            r_sum += r_dotp[i];
                        }

                        r_dotprod_pad.push_back(r_sum);

                        auto q_share = pre_out->mask + pre_out->mask_prod;
                        for (size_t i = 0; i < g->in1.size(); ++i)
                        {
                            auto win1 = g->in1[i];             // index for masked value for left input wires
                            auto win2 = g->in2[i];             // index for masked value for right input wires
                            auto &m_in1 = preproc[win1]->mask; // masks for left wires
                            auto &m_in2 = preproc[win2]->mask; // masks for right wires
                            q_share -= (m_in1 * wires[win2] + m_in2 * wires[win1]);
                            q_share.add((wires[win1] * wires[win2]), id);
                        }
                        for (int i = 1; i <= nP; i++)
                        {
                            q_share.addWithAdder(r_dotp[id - 1], id, i);
                        }
                        dotprod_nonTP.push_back(q_share.valueAt());
                        qsh[g->out] = q_share;
                    }
                    break;
                }
                default:
                    break;
                }
            }
        }
    }

    void BoolEval::evaluateGatesAtDepthPartyRecv(size_t depth,
                                                 std::vector<BoolRing> mult_all, std::vector<BoolRing> r_mult_pad,
                                                 std::vector<BoolRing> mult3_all, std::vector<BoolRing> r_mult3_pad,
                                                 std::vector<BoolRing> mult4_all, std::vector<BoolRing> r_mult4_pad,
                                                 std::vector<BoolRing> dotprod_all, std::vector<BoolRing> r_dotprod_pad, ThreadPool &tpool)
    {
        size_t idx_mult = 0;
        size_t idx_mult3 = 0;
        size_t idx_mult4 = 0;
        size_t idx_dotprod = 0;

        for (size_t i = 0; i < vwires.size(); ++i)
        {
            auto &wires = vwires[i];
            auto &qval = vqval[i];
            for (auto &gate : circ.gates_by_level[depth])
            {
                switch (gate->type)
                {
                case common::utils::GateType::kAdd:
                {
                    auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                    wires[g->out] = wires[g->in1] + wires[g->in2];
                    qval[g->out] = 0;
                    break;
                }

                case common::utils::GateType::kSub:
                {
                    auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                    wires[g->out] = wires[g->in1] - wires[g->in2];
                    qval[g->out] = 0;
                    break;
                }

                case common::utils::GateType::kConstAdd:
                {
                    auto *g = static_cast<common::utils::ConstOpGate<BoolRing> *>(gate.get());
                    wires[g->out] = wires[g->in] + g->cval;
                    break;
                }

                case common::utils::GateType::kConstMul:
                {
                    auto *g = static_cast<common::utils::ConstOpGate<BoolRing> *>(gate.get());
                    wires[g->out] = wires[g->in] * g->cval;
                    break;
                }

                case common::utils::GateType::kMul:
                {
                    auto *g = static_cast<common::utils::FIn2Gate *>(gate.get());
                    qval[g->out] = mult_all[idx_mult];
                    wires[g->out] = qval[g->out] - r_mult_pad[idx_mult];
                    idx_mult++;
                    break;
                }
                case common::utils::GateType::kMul3:
                {
                    auto *g = static_cast<common::utils::FIn3Gate *>(gate.get());
                    qval[g->out] = mult3_all[idx_mult3];
                    wires[g->out] = qval[g->out] - r_mult3_pad[idx_mult3];
                    idx_mult3++;
                    break;
                }
                case common::utils::GateType::kMul4:
                {
                    auto *g = static_cast<common::utils::FIn4Gate *>(gate.get());
                    qval[g->out] = mult4_all[idx_mult4];
                    wires[g->out] = qval[g->out] - r_mult4_pad[idx_mult4];
                    idx_mult4++;
                    break;
                }
                case common::utils::GateType::kDotprod:
                {
                    auto *g = static_cast<common::utils::SIMDGate *>(gate.get());
                    qval[g->out] = dotprod_all[idx_dotprod];
                    wires[g->out] = qval[g->out] - r_dotprod_pad[idx_dotprod];
                    idx_dotprod++;
                    break;
                }
                default:
                    break;
                }
            }
        }
    }

    void BoolEval::evaluateGatesAtDepth(size_t depth, io::NetIOMP &network, ThreadPool &tpool)
    {
        size_t mult_num = 0;
        size_t mult3_num = 0;
        size_t mult4_num = 0;
        size_t dotprod_num = 0;

        for (auto &gate : circ.gates_by_level[depth])
        {
            switch (gate->type)
            {
            case common::utils::GateType::kMul:
            {
                mult_num++;
                break;
            }

            case common::utils::GateType::kMul3:
            {
                mult3_num++;
                break;
            }

            case common::utils::GateType::kMul4:
            {
                mult4_num++;
                break;
            }

            case common::utils::GateType::kDotprod:
            {
                dotprod_num++;
                break;
            }

            case common::utils::GateType::kAdd:
            {
                break;
            }
            }
        }

        mult_num *= vwires.size(); mult3_num *= vwires.size(); mult4_num *= vwires.size(); dotprod_num *= vwires.size();
        size_t total_comm = mult_num + mult3_num + mult4_num + dotprod_num;
        std::vector<BoolRing> mult_nonTP;
        std::vector<BoolRing> mult3_nonTP;
        std::vector<BoolRing> mult4_nonTP;
        std::vector<BoolRing> dotprod_nonTP;

        std::vector<BoolRing> r_mult_pad;
        std::vector<BoolRing> r_mult3_pad;
        std::vector<BoolRing> r_mult4_pad;
        std::vector<BoolRing> r_dotprod_pad;

        if (id != 0)
        {
            evaluateGatesAtDepthPartySend(depth, mult_nonTP, r_mult_pad,
                                          mult3_nonTP, r_mult3_pad,
                                          mult4_nonTP, r_mult4_pad,
                                          dotprod_nonTP, r_dotprod_pad, tpool);

            std::vector<BoolRing> online_comm_to_TP(total_comm);

            for (size_t i = 0; i < mult_num; i++)
            {
                online_comm_to_TP[i] = mult_nonTP[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                online_comm_to_TP[i + mult_num] = mult3_nonTP[i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num] = mult4_nonTP[i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                online_comm_to_TP[i + mult_num + mult3_num + mult4_num] = dotprod_nonTP[i];
            }

            size_t per_party_comm = floor(total_comm / nP);
            size_t last_party_comm = per_party_comm + (total_comm % nP);

            for (size_t pid = 1; pid <= nP; pid++)
            {
                if (id == pid)
                {
                    continue;
                }
                if (pid != nP)
                {
                    std::vector<BoolRing> online_comm_to_party(per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        online_comm_to_party[i] = online_comm_to_TP[(pid - 1) * per_party_comm + i];
                    }
                    auto net_data = BoolRing::pack(online_comm_to_party.data(), per_party_comm);
                    network.send(pid, net_data.data(), sizeof(uint8_t) * net_data.size());
                }
                else
                {
                    std::vector<BoolRing> online_comm_to_party(last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        online_comm_to_party[i] = online_comm_to_TP[(pid - 1) * per_party_comm + i];
                    }
                    auto net_data = BoolRing::pack(online_comm_to_party.data(), last_party_comm);
                    network.send(pid, net_data.data(), sizeof(uint8_t) * net_data.size());
                }
            }

            std::vector<BoolRing> agg_values_send(per_party_comm, 0);
            std::vector<BoolRing> agg_values_send_last(last_party_comm, 0);
            for (size_t pid = 1; pid <= nP; pid++)
            {
                if (id == pid)
                {
                    if (id != nP)
                    {
                        for (size_t i = 0; i < per_party_comm; i++)
                        {
                            agg_values_send[i] += online_comm_to_TP[(pid - 1) * per_party_comm + i];
                        }
                    }
                    else
                    {
                        for (size_t i = 0; i < last_party_comm; i++)
                        {
                            agg_values_send_last[i] += online_comm_to_TP[(pid - 1) * per_party_comm + i];
                        }
                    }
                    continue;
                }
                if (id != nP)
                {
                    size_t nbytes = (per_party_comm + 7) / 8;
                    std::vector<uint8_t> net_data(nbytes);
                    network.recv(pid, net_data.data(), nbytes);
                    auto online_comm_to_party_recv = BoolRing::unpack(net_data.data(), per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        agg_values_send[i] += online_comm_to_party_recv[i];
                    }
                }
                else
                {
                    size_t nbytes = (last_party_comm + 7) / 8;
                    std::vector<uint8_t> net_data(nbytes);
                    network.recv(pid, net_data.data(), nbytes);
                    auto online_comm_to_party_recv = BoolRing::unpack(net_data.data(), last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        agg_values_send_last[i] += online_comm_to_party_recv[i];
                    }
                }
            }

            for (size_t pid = 1; pid <= nP; pid++)
            {
                if (id == pid)
                {
                    continue;
                }
                if (id != nP)
                {
                    auto net_data = BoolRing::pack(agg_values_send.data(), per_party_comm);
                    network.send(pid, net_data.data(), sizeof(uint8_t) * net_data.size());
                }
                else
                {
                    auto net_data = BoolRing::pack(agg_values_send_last.data(), last_party_comm);
                    network.send(pid, net_data.data(), sizeof(uint8_t) * net_data.size());
                }
            }

            std::vector<BoolRing> agg_values(total_comm, 0);
            for (size_t pid = 1; pid <= nP; pid++)
            {
                if (id == pid)
                {
                    if (id != nP)
                    {
                        for (size_t i = 0; i < per_party_comm; i++)
                        {
                            agg_values[(pid - 1) * per_party_comm + i] += agg_values_send[i];
                        }
                    }
                    else
                    {
                        for (size_t i = 0; i < last_party_comm; i++)
                        {
                            agg_values[(pid - 1) * per_party_comm + i] += agg_values_send_last[i];
                        }
                    }
                    continue;
                }
                if (pid != nP)
                {
                    size_t nbytes = (per_party_comm + 7) / 8;
                    std::vector<uint8_t> net_data(nbytes);
                    network.recv(pid, net_data.data(), nbytes);
                    auto agg_values_recv = BoolRing::unpack(net_data.data(), per_party_comm);
                    for (size_t i = 0; i < per_party_comm; i++)
                    {
                        agg_values[(pid - 1) * per_party_comm + i] += agg_values_recv[i];
                    }
                }
                else
                {
                    size_t nbytes = (last_party_comm + 7) / 8;
                    std::vector<uint8_t> net_data(nbytes);
                    network.recv(pid, net_data.data(), nbytes);
                    auto agg_values_recv = BoolRing::unpack(net_data.data(), last_party_comm);
                    for (size_t i = 0; i < last_party_comm; i++)
                    {
                        agg_values[(pid - 1) * per_party_comm + i] += agg_values_recv[i];
                    }
                }
            }

            std::vector<BoolRing> mult_all(mult_num);
            std::vector<BoolRing> mult3_all(mult3_num);
            std::vector<BoolRing> mult4_all(mult4_num);
            std::vector<BoolRing> dotprod_all(dotprod_num);

            for (size_t i = 0; i < mult_num; i++)
            {
                mult_all[i] = agg_values[i];
            }
            for (size_t i = 0; i < mult3_num; i++)
            {
                mult3_all[i] = agg_values[mult_num + i];
            }
            for (size_t i = 0; i < mult4_num; i++)
            {
                mult4_all[i] = agg_values[mult3_num + mult_num + i];
            }
            for (size_t i = 0; i < dotprod_num; i++)
            {
                dotprod_all[i] = agg_values[mult4_num +
                                            mult3_num +
                                            mult_num + i];
            }
            evaluateGatesAtDepthPartyRecv(depth,
                                          mult_all, r_mult_pad,
                                          mult3_all, r_mult3_pad,
                                          mult4_all, r_mult4_pad,
                                          dotprod_all, r_dotprod_pad, tpool);
        }
    }

    void BoolEval::evaluateAllLevels(io::NetIOMP &network, ThreadPool &tpool)
    {
        for (size_t i = 0; i < circ.gates_by_level.size(); ++i)
        {
            evaluateGatesAtDepth(i, network, tpool);
        }
    }

    std::vector<std::vector<BoolRing>> BoolEval::getOutputShares()
    {
        std::vector<std::vector<BoolRing>> outputs(
            vwires.size(), std::vector<BoolRing>(circ.outputs.size()));

        for (size_t i = 0; i < vwires.size(); ++i)
        {
            const auto &wires = vwires[i];
            for (size_t j = 0; j < circ.outputs.size(); ++j)
            {
                outputs[i][j] = wires[circ.outputs[j]];
            }
        }

        return outputs;
    }
}; // namespace asterisk
