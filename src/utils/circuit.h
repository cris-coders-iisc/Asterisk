#pragma once

#include <algorithm>
#include <array>
#include <boost/format.hpp>
#include <cmath>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "helpers.h"
#include "types.h"

namespace common::utils {

using wire_t = size_t;

enum GateType {
  kInp,
  kAdd,
  kMul,
  kMul3,
  kMul4,
  kSub,
  kConstAdd,
  kConstMul,
  kRelu,
  kMsb,
  kEqz,
  kLtz,
  kDotprod,
  kTrdotp,
  kInvalid,
  NumGates
};

std::ostream& operator<<(std::ostream& os, GateType type);

// Gates represent primitive operations.
// All gates have one output.
struct Gate {
  GateType type{GateType::kInvalid};
  wire_t out;

  Gate() = default;
  Gate(GateType type, wire_t out);

  virtual ~Gate() = default;
};

// Represents a gate with fan-in 2.
struct FIn2Gate : public Gate {
  wire_t in1{0};
  wire_t in2{0};

  FIn2Gate() = default;
  FIn2Gate(GateType type, wire_t in1, wire_t in2, wire_t out);
};

struct FIn3Gate : public Gate {
  wire_t in1{0};
  wire_t in2{0};
  wire_t in3{0};

  FIn3Gate() = default;
  FIn3Gate(GateType type, wire_t in1, wire_t in2, wire_t in3, wire_t out);
};

struct FIn4Gate : public Gate {
  wire_t in1{0};
  wire_t in2{0};
  wire_t in3{0};
  wire_t in4{0};

  FIn4Gate() = default;
  FIn4Gate(GateType type, wire_t in1, wire_t in2, 
            wire_t in3, wire_t in4, wire_t out);
};

// Represents a gate with fan-in 1.
struct FIn1Gate : public Gate {
  wire_t in{0};

  FIn1Gate() = default;
  FIn1Gate(GateType type, wire_t in, wire_t out);
};

// Represents a gate used to denote SIMD operations.
// These type is used to represent operations that take vectors of inputs but
// might not necessarily be SIMD e.g., dot product.
struct SIMDGate : public Gate {
  std::vector<wire_t> in1{0};
  std::vector<wire_t> in2{0};

  SIMDGate() = default;
  SIMDGate(GateType type, std::vector<wire_t> in1, std::vector<wire_t> in2,
           wire_t out);
};

// Represents gates where one input is a constant.
template <class R>
struct ConstOpGate : public Gate {
  wire_t in{0};
  R cval;

  ConstOpGate() = default;
  ConstOpGate(GateType type, wire_t in, R cval, wire_t out)
      : Gate(type, out), in(in), cval(std::move(cval)) {}
};

using gate_ptr_t = std::shared_ptr<Gate>;

// Gates ordered by multiplicative depth.
//
// Addition gates are not considered to increase the depth.
// Moreover, if gates_by_level[l][i]'s output is input to gates_by_level[l][j]
// then i < j.
struct LevelOrderedCircuit {
  size_t num_gates;
  std::array<uint64_t, GateType::NumGates> count;
  std::vector<wire_t> outputs;
  std::vector<std::vector<gate_ptr_t>> gates_by_level;

  friend std::ostream& operator<<(std::ostream& os,
                                  const LevelOrderedCircuit& circ);
};

// Represents an arithmetic circuit.
template <class R>
class Circuit {
  std::vector<wire_t> outputs_;
  std::vector<gate_ptr_t> gates_;

  bool isWireValid(wire_t wid) { return wid < gates_.size(); }

 public:
  Circuit() = default;

  // Methods to manually build a circuit.
  wire_t newInputWire() {
    wire_t wid = gates_.size();
    gates_.push_back(std::make_shared<Gate>(GateType::kInp, wid));
    return wid;
  }

  void setAsOutput(wire_t wid) {
    if (!isWireValid(wid)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    outputs_.push_back(wid);
  }

  // Function to add a gate with fan-in 2.
  wire_t addGate(GateType type, wire_t input1, wire_t input2) {
    if (type != GateType::kAdd && type != GateType::kMul &&
        type != GateType::kSub) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (!isWireValid(input1) || !isWireValid(input2)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<FIn2Gate>(type, input1, input2, output));

    return output;
  }

  // Function to add a gate with fan-in 3.
  wire_t addGate(GateType type, wire_t input1, wire_t input2, wire_t input3) {
    if (type != GateType::kMul3) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (!isWireValid(input1) || !isWireValid(input2) || !isWireValid(input3)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<FIn3Gate>(type, input1, input2, input3, output));

    return output;
  }

  // Function to add a gate with fan-in 4.
  wire_t addGate(GateType type, wire_t input1, wire_t input2, 
                                wire_t input3, wire_t input4) {
    if (type != GateType::kMul4) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (!isWireValid(input1) || !isWireValid(input2) 
        || !isWireValid(input3) || !isWireValid(input4)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<FIn4Gate>(type, input1, input2, 
                                          input3, input4, output));

    return output;
  }

  // Function to add a gate with one input from a wire and a second constant
  // input.
  wire_t addConstOpGate(GateType type, wire_t wid, R cval) {
    if (type != kConstAdd && type != kConstMul) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (!isWireValid(wid)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<ConstOpGate<R>>(type, wid, cval, output));

    return output;
  }

  // Function to add a single input gate.
  wire_t addGate(GateType type, wire_t input) {
    if (type != GateType::kRelu && type != GateType::kMsb
        && type != GateType::kEqz && type != GateType::kLtz) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (!isWireValid(input)) {
      throw std::invalid_argument("Invalid wire ID.");
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<FIn1Gate>(type, input, output));

    return output;
  }

  // Function to add a multiple fan-in gate.
  wire_t addGate(GateType type, const std::vector<wire_t>& input1,
                 const std::vector<wire_t>& input2) {
    if (type != GateType::kDotprod && type != GateType::kTrdotp) {
      throw std::invalid_argument("Invalid gate type.");
    }

    if (input1.size() != input2.size()) {
      throw std::invalid_argument("Expected same length inputs.");
    }

    for (size_t i = 0; i < input1.size(); ++i) {
      if (!isWireValid(input1[i]) || !isWireValid(input2[i])) {
        throw std::invalid_argument("Invalid wire ID.");
      }
    }

    wire_t output = gates_.size();
    gates_.push_back(std::make_shared<SIMDGate>(type, input1, input2, output));
    return output;
  }

  // Level ordered gates are helpful for evaluation.
  [[nodiscard]] LevelOrderedCircuit orderGatesByLevel() const {
    LevelOrderedCircuit res;
    res.outputs = outputs_;
    res.num_gates = gates_.size();

    // Map from output wire id to multiplicative depth/level.
    // Input gates have a depth of 0.
    std::vector<size_t> gate_level(res.num_gates, 0);
    size_t depth = 0;

    // This assumes that if gates_[i]'s output is input to gates_[j] then
    // i < j.
    for (const auto& gate : gates_) {
      switch (gate->type) {
        case GateType::kAdd:
        case GateType::kSub: {
          const auto* g = static_cast<FIn2Gate*>(gate.get());
          gate_level[g->out] = std::max(gate_level[g->in1], gate_level[g->in2]);
          break;
        }

        case GateType::kMul: {
          const auto* g = static_cast<FIn2Gate*>(gate.get());
          gate_level[g->out] =
              std::max(gate_level[g->in1], gate_level[g->in2]) + 1;
          break;
        }
        case GateType::kMul3: {
          const auto* g = static_cast<FIn3Gate*>(gate.get());
          size_t gate_depth = std::max(gate_level[g->in1], gate_level[g->in2]);
          gate_depth = std::max(gate_depth, gate_level[g->in3]);
          gate_level[g->out] = gate_depth + 1;
          break;
        }

        case GateType::kMul4: {
          const auto* g = static_cast<FIn4Gate*>(gate.get());
          size_t gate_depth = std::max(gate_level[g->in1], gate_level[g->in2]);
          gate_depth = std::max(gate_depth, gate_level[g->in3]);
          gate_depth = std::max(gate_depth, gate_level[g->in4]);
          gate_level[g->out] = gate_depth + 1;
          break;
        }

        case GateType::kConstAdd:
        case GateType::kConstMul: {
          const auto* g = static_cast<ConstOpGate<R>*>(gate.get());
          gate_level[g->out] = gate_level[g->in];
          break;
        }

        case GateType::kEqz: {
          const auto* g = static_cast<FIn1Gate*>(gate.get());
          gate_level[g->out] = gate_level[g->in] + 1;
          break;
        }

        case GateType::kLtz: {
          const auto* g = static_cast<FIn1Gate*>(gate.get());
          gate_level[g->out] = gate_level[g->in] + 1;
          break;
        }

        case GateType::kRelu: {
          const auto* g = static_cast<FIn1Gate*>(gate.get());
          gate_level[g->out] = gate_level[g->in] + 1;
          break;
        }

        case GateType::kMsb: {
          const auto* g = static_cast<FIn1Gate*>(gate.get());
          gate_level[g->out] = gate_level[g->in] + 1;
          break;
        }

        case GateType::kDotprod:
        case GateType::kTrdotp: {
          const auto* g = static_cast<SIMDGate*>(gate.get());
          size_t gate_depth = 0;
          for (size_t i = 0; i < g->in1.size(); ++i) {
            gate_depth = std::max(
                {gate_level[g->in1[i]], gate_level[g->in2[i]], gate_depth});
          }
          gate_level[g->out] = gate_depth + 1;
          break;
        }

        default:
          break;
      }

      depth = std::max(depth, gate_level[gate->out]);
    }

    std::fill(res.count.begin(), res.count.end(), 0);

    std::vector<std::vector<gate_ptr_t>> gates_by_level(depth + 1);
    for (const auto& gate : gates_) {
      res.count[gate->type]++;
      gates_by_level[gate_level[gate->out]].push_back(gate);
    }

    res.gates_by_level = std::move(gates_by_level);

    return res;
  }

  // Evaluate circuit on plaintext inputs.
  [[nodiscard]] std::vector<R> evaluate(
      const std::unordered_map<wire_t, R>& inputs) const {
    auto level_circ = orderGatesByLevel();
    std::vector<R> wires(level_circ.num_gates);

    auto num_inp_gates = level_circ.count[GateType::kInp];
    if (inputs.size() != num_inp_gates) {
      throw std::invalid_argument(boost::str(
          boost::format("Expected %1% inputs but received %2% inputs.") %
          num_inp_gates % inputs.size()));
    }

    for (const auto& level : level_circ.gates_by_level) {
      for (const auto& gate : level) {
        switch (gate->type) {
          case GateType::kInp: {
            wires[gate->out] = inputs.at(gate->out);
            break;
          }

          case GateType::kMul: {
            auto* g = static_cast<FIn2Gate*>(gate.get());
            wires[g->out] = wires[g->in1] * wires[g->in2];
            break;
          }

          case GateType::kMul3: {
            auto* g = static_cast<FIn3Gate*>(gate.get());
            wires[g->out] = wires[g->in1] * wires[g->in2] * wires[g->in3];
            break;
          }

          case GateType::kMul4: {
            auto* g = static_cast<FIn4Gate*>(gate.get());
            wires[g->out] = wires[g->in1] * wires[g->in2] 
                              * wires[g->in3] * wires[g->in4];
            break;
          }

          case GateType::kAdd: {
            auto* g = static_cast<FIn2Gate*>(gate.get());
            wires[g->out] = wires[g->in1] + wires[g->in2];
            break;
          }

          case GateType::kSub: {
            auto* g = static_cast<FIn2Gate*>(gate.get());
            wires[g->out] = wires[g->in1] - wires[g->in2];
            break;
          }

          case GateType::kConstAdd: {
            auto* g = static_cast<ConstOpGate<R>*>(gate.get());
            wires[g->out] = wires[g->in] + g->cval;
            break;
          }

          case GateType::kConstMul: {
            auto* g = static_cast<ConstOpGate<R>*>(gate.get());
            wires[g->out] = wires[g->in] * g->cval;
            break;
          }

          case GateType::kEqz: {
            auto* g = static_cast<FIn1Gate*>(gate.get());
            if(wires[g->in] == 0) {
              wires[g->out] = 1;
            }
            else {
              wires[g->out] = 0;
            }
            break;
          }

          case GateType::kLtz: {
            auto* g = static_cast<FIn1Gate*>(gate.get());

            if constexpr (std::is_same_v<R, BoolRing>) {
              wires[g->out] = wires[g->in];
            } else {
              std::vector<BoolRing> bin = bitDecomposeTwo(wires[g->in]);
              wires[g->out] = bin[63].val();
            }
            break;
          }

          case GateType::kRelu: {
            // ReLU gates don't make sense for boolean rings.
            if constexpr (std::is_same_v<R, BoolRing>) {
              throw std::runtime_error("ReLU gates are invalid for BoolRing.");
            } else {
              auto* g = static_cast<FIn1Gate*>(gate.get());
              std::vector<BoolRing> bin = bitDecomposeTwo(wires[g->in]);

              if (bin[63].val())
                wires[g->out] = 0;
              else
                wires[g->out] = wires[g->in];
            }
            break;
          }

          case GateType::kMsb: {
            auto* g = static_cast<FIn1Gate*>(gate.get());

            if constexpr (std::is_same_v<R, BoolRing>) {
              wires[g->out] = wires[g->in];
            } else {
              std::vector<BoolRing> bin = bitDecomposeTwo(wires[g->in]);
              wires[g->out] = bin[63].val();
            }
            break;
          }

          case GateType::kDotprod: {
            auto* g = static_cast<SIMDGate*>(gate.get());
            for (size_t i = 0; i < g->in1.size(); i++) {
              wires[g->out] += wires[g->in1.at(i)] * wires[g->in2.at(i)];
            }
            break;
          }

          case GateType::kTrdotp: {
            // Truncation makes sense only for non-boolean rings.
            if constexpr (std::is_same_v<R, BoolRing>) {
              throw std::runtime_error(
                  "Truncation gates are invalid for BoolRing.");
            } else {
              auto* g = static_cast<SIMDGate*>(gate.get());
              for (size_t i = 0; i < g->in1.size(); i++) {
                auto temp = wires[g->in1.at(i)] * wires[g->in2.at(i)];
                wires[g->out] += temp;
              }
              uint64_t temp = conv<uint64_t>(wires[g->out]);
              temp = temp >> FRACTION;
              wires[g->out] = R(temp);
            }
            break;
          }

          default: {
            throw std::runtime_error("Invalid gate type.");
          }
        }
      }
    }

    std::vector<R> outputs;
    for (auto i : level_circ.outputs) {
      outputs.push_back(wires[i]);
    }

    return outputs;
  }

   static Circuit generatePrefixAND() {
    Circuit circ;
    size_t k = 64;
    std::vector<wire_t> input(k);
    std::vector<wire_t> inp_d(k);
    for (int i = 0; i < k; i++) {
      input[i] = circ.newInputWire();
    }
    for (int i = 0; i < k; i++) {
      inp_d[i] = circ.newInputWire();
    }
    
    
    R zero = 0;
    R one = 1;
    std::vector<wire_t> leveli(k);
    leveli = std::move(input);
    
    
    // For PrefixAND
    for(size_t level = 1; level <= log(k)/log(4); level++) {
      std::vector<wire_t> level_next(k);
        
      for(size_t j = 1; j <= k/pow(4, level); j++) {
            
        size_t p = (j-1) * pow(4, level);
        size_t q = (j-1) * pow(4, level) + pow(4,level - 1);
        size_t r = (j-1) * pow(4, level) + 2 * pow(4,level - 1);
        size_t s = (j-1) * pow(4, level) + 3 * pow(4,level - 1);
        
        for(size_t i = 0; i < pow(4, level - 1); i++) {
          // level_next[p + i] = circ.addConstOpGate(GateType::kConstAdd, leveli[p+i], zero);
          level_next[p + i] = leveli[p+i];
          level_next[q + i] = circ.addGate(GateType::kMul, leveli[q], leveli[q+i]);
          level_next[r + i] = circ.addGate(GateType::kMul3, leveli[q], leveli[r], leveli[r+i]);
          level_next[s + i] = circ.addGate(GateType::kMul4, leveli[q], leveli[r], leveli[s], leveli[s+i]);
        }
      }
      leveli = std::move(level_next);
    }
    
    // For PrefixOR
    std::vector<wire_t> wv(k);
    for(size_t i = 0; i < k; i++) {
      wv[i] = circ.addConstOpGate(GateType::kConstAdd, leveli[i], one);
    }
    std::vector<wire_t> wz(k);
    wz[0] = circ.addConstOpGate(GateType::kConstAdd, wv[0], zero);
    for(size_t i = 1; i < k; i++) {
      wz[i] = circ.addGate(GateType::kAdd, wv[i], wv[i-1]);
    }
    wire_t wu;
    wu = circ.addGate(GateType::kDotprod, wz, inp_d);
    wire_t wnu;
    wnu = circ.addConstOpGate(GateType::kConstAdd, wu, one);
    circ.setAsOutput(wnu);
    return circ;
  }

  static Circuit generateParaPrefixAND(int repeat) {
    Circuit circ;
    size_t k = 64;
    std::vector<wire_t> input(repeat * k);
    for(int rep = 0; rep < repeat; rep++) {
      for (int i = 0; i < k; i++) {
        input[(rep * (k)) + i] = circ.newInputWire();
      }
    }
    R zero = 0;
    
    std::vector<wire_t> leveli(repeat * k);
    leveli = std::move(input);
    
    for(size_t level = 1; level <= log(k)/log(4); level++) {
        std::vector<wire_t> level_next(repeat * k);
          for(size_t j = 1; j <= repeat * k/pow(4, level); j++) {
            size_t p = (j-1) * pow(4, level);
            size_t q = (j-1) * pow(4, level) + pow(4,level - 1);
            size_t r = (j-1) * pow(4, level) + 2 * pow(4,level - 1);
            size_t s = (j-1) * pow(4, level) + 3 * pow(4,level - 1);
        
            for(size_t i = 0; i < pow(4, level -1); i++) {
              level_next[p + i] = circ.addConstOpGate(GateType::kConstAdd, leveli[p+i], zero);
              level_next[q + i] = circ.addGate(GateType::kMul, leveli[q-1], leveli[q+i]);
              level_next[r + i] = circ.addGate(GateType::kMul3, leveli[q-1], leveli[r-1], leveli[r+i]);
              level_next[s + i] = circ.addGate(GateType::kMul4, leveli[q-1], leveli[r-1], leveli[s-1], leveli[s+i]);
            }
          }
          leveli = std::move(level_next);
          if(level == log(k)/log(4)) {
            for(int rep = 0; rep < repeat; rep++) {
              for(size_t i = 1; i < k; i++) {
                circ.setAsOutput(leveli[(rep * k) + i]);
              }
            }
          }
    }
          std::vector<wire_t> lastAND(repeat);
          for(int rep = 0; rep < repeat; rep++) {
            lastAND[rep] = circ.addGate(GateType::kMul, leveli[1], leveli[2]);
          }
    return circ;
  }


  static Circuit generateParaPrefixOR(int repeat) {
    Circuit circ;
    size_t k = 64;
    std::vector<wire_t> input(repeat * k);
    for(int rep = 0; rep < repeat; rep++) {
      for (int i = 0; i < k; i++) {
        input[rep*k + i] = circ.newInputWire();
      }
    }
    std::vector<std::vector<wire_t>> inp_d(repeat, std::vector<wire_t>(k));
    for (int i=0; i<repeat; i++) {
      for (int j=0; j<k; j++) {
        inp_d[i][j] = circ.newInputWire();
      }
    }
    R zero = 0;
    R one = 1;
    
    std::vector<wire_t> leveli(repeat * k);
    leveli = std::move(input);
    
    for(size_t level = 1; level <= log(k)/log(4); level++) {
        std::vector<wire_t> level_next(repeat * k);
          for(size_t j = 1; j <= repeat * k/pow(4, level); j++) {
            size_t p = (j-1) * pow(4, level);
            size_t q = (j-1) * pow(4, level) + pow(4,level - 1);
            size_t r = (j-1) * pow(4, level) + 2 * pow(4,level - 1);
            size_t s = (j-1) * pow(4, level) + 3 * pow(4,level - 1);
        
            for(size_t i = 0; i < pow(4, level -1); i++) {
              level_next[p + i] = circ.addConstOpGate(GateType::kConstAdd, leveli[p+i], zero);
              level_next[q + i] = circ.addGate(GateType::kMul, leveli[q-1], leveli[q+i]);
              level_next[r + i] = circ.addGate(GateType::kMul3, leveli[q-1], leveli[r-1], leveli[r+i]);
              level_next[s + i] = circ.addGate(GateType::kMul4, leveli[q-1], leveli[r-1], leveli[s-1], leveli[s+i]);
            }
          }
          leveli = std::move(level_next);
    }          

    // For PrefixOR
    std::vector<std::vector<wire_t>> wv(repeat, std::vector<wire_t>(k));
    for(size_t i = 0; i < repeat; i++) {
      for(size_t j=0; j<k; j++ ) {
        wv[i][j] = circ.addConstOpGate(GateType::kConstAdd, leveli[i*k+j], one);
      }      
    }

    std::vector<std::vector<wire_t>> wz(repeat, std::vector<wire_t>(k));  
    for(size_t i=0; i< repeat; i++) {
      wz[i][0] = circ.addConstOpGate(GateType::kConstAdd, wv[i][0], zero);
      for(size_t j = 1; j < k; j++) {
        wz[i][j] = circ.addGate(GateType::kAdd, wv[i][j], wv[i][j-1]);
      }
    }
    
    std::vector<wire_t> inp1(k*repeat), inp2(k*repeat);
    for(size_t i=0; i< repeat; i++) {
      inp1.insert(inp1.end(),wz[i].begin(),wz[i].end());
      inp2.insert(inp2.end(),inp_d[i].begin(),inp_d[i].end());
    }
    wire_t res = circ.addGate(GateType::kDotprod, inp1, inp2);

    circ.setAsOutput(res);
    return circ;
    
  }

   static Circuit generateMultK() {
    Circuit circ;
    size_t k = 64;
    std::vector<wire_t> input(k);
    for (int i = 0; i < k; i++) {
      input[i] = circ.newInputWire();
    }
    
    std::vector<wire_t> leveli(k);
    leveli = std::move(input);

    for(size_t level = 1; level <= log(k)/log(4); level++) {
      std::vector<wire_t> level_next(k/pow(4, level));
      for(size_t j = 1; j <= k / pow(4, level); j++) {
        level_next[j-1] = circ.addGate(GateType::kMul4, leveli[(4 * j)-4], leveli[(4 * j)-3],
                                               leveli[(4 * j)-2], leveli[(4 * j) - 1]);
      }
      leveli.resize(k/pow(4, level));
      leveli = std::move(level_next);
    }
    circ.setAsOutput(leveli[0]);
    return circ;
  }


  static Circuit generatePPA() {
    Circuit circ;
    std::vector<wire_t> input_a(64);
    std::vector<wire_t> input_b(64);

    std::vector<wire_t> loc_p, loc_g;
    for (int i = 0; i < 64; i++) {
      input_a[i] = circ.newInputWire();
    }

    for (int i = 0; i < 64; i++) {
      input_b[i] = circ.newInputWire();
    }

    // input_a[0] stores the lsb.
    for (int i = 0; i < 64; i++) {
      auto p_id = circ.addGate(GateType::kAdd, input_a[i], input_b[i]);
      loc_p.push_back(p_id);

      auto g_id = circ.addGate(GateType::kMul, input_a[i], input_b[i]);
      loc_g.push_back(g_id);
    }

    for (int level = 1; level <= 6; level++) {
      for (int count = 1; count <= 64 / std::pow(2, level); count++) {
        int temp =
            std::pow(2, level - 1) + (count - 1) * std::pow(2, level) - 1;
        for (int i = 0; i < std::pow(2, level - 1); i++) {
          auto w1 =
              circ.addGate(GateType::kMul, loc_p[temp + i + 1], loc_g[temp]);

          auto w2 = circ.addGate(GateType::kAdd, loc_g[temp + i + 1], w1);

          loc_g[temp + i + 1] = w2;
          auto w3 =
              circ.addGate(GateType::kMul, loc_p[temp + i + 1], loc_p[temp]);

          loc_p[temp + i + 1] = w3;
        }
      }
    }

    std::vector<wire_t> S;

    S.push_back(circ.addGate(GateType::kAdd, input_a[0], input_b[0]));
    for (int i = 1; i < 64; i++) {
      auto w = circ.addGate(GateType::kAdd, input_a[i], input_b[i]);
      S.push_back(circ.addGate(GateType::kAdd, w, loc_g[i - 1]));
    }

    for (int i = 0; i < 64; i++) {
      circ.setAsOutput(S[i]);
    }
    return circ;
  }

  static Circuit generatePPAMSB() {
    Circuit circ;
    std::vector<wire_t> input_a(64);
    std::vector<wire_t> input_b(64);

    std::vector<wire_t> loc_p, loc_g;
    for (int i = 0; i < 64; i++) {
      input_a[i] = circ.newInputWire();
    }

    for (int i = 0; i < 64; i++) {
      input_b[i] = circ.newInputWire();
    }

    // input_a[0] stores the lsb.
    for (int i = 0; i < 64; i++) {
      auto p_id = circ.addGate(GateType::kAdd, input_a[i], input_b[i]);
      loc_p.push_back(p_id);
      auto g_id = circ.addGate(GateType::kMul, input_a[i], input_b[i]);
      loc_g.push_back(g_id);
    }

    for (int level = 1; level <= 6; level++) {
      for (int count = 1; count <= 64 / std::pow(2, level); count++) {
        int temp =
            std::pow(2, level - 1) + (count - 1) * std::pow(2, level) - 1;
        int offset = std::pow(2, level - 1);
        if (count < 64 / std::pow(2, level)) {
          auto w1 =
              circ.addGate(GateType::kMul, loc_p[temp + offset], loc_g[temp]);
          auto w2 = circ.addGate(GateType::kAdd, loc_g[temp + offset], w1);
          loc_g[temp + offset] = w2;

          auto w3 =
              circ.addGate(GateType::kMul, loc_p[temp + offset], loc_p[temp]);
          loc_p[temp + offset] = w3;
        } else {
          if (level != 1) {
            auto w1 = circ.addGate(GateType::kMul, loc_p[62], loc_g[temp]);
            auto w2 = circ.addGate(GateType::kAdd, loc_g[62], w1);
            loc_g[62] = w2;

            auto w3 = circ.addGate(GateType::kMul, loc_p[62], loc_p[temp]);
            loc_p[62] = w3;
          }
        }
      }
    }
    auto w = circ.addGate(GateType::kAdd, input_a[63], input_b[63]);

    auto msb = circ.addGate(GateType::kAdd, w, loc_g[62]);

    circ.setAsOutput(msb);
    return circ;
  }

  static Circuit generateAuction(int N) {
    Circuit circ;
    // shuffle
    std::vector<std::vector<wire_t>> M_pi(N, std::vector<wire_t>(N));
    std::vector<wire_t> x(N);
    for(size_t i = 0; i < N; i++) {
        for(size_t j = 0; j < N; j++) {
            M_pi[i][j] = circ.newInputWire();
        }
    }
    for(size_t i = 0; i < N; i++) {
      x[i] = circ.newInputWire();
    }
    // std::vector<wire_t> pi_x(N);
    // for(int i = 0; i < N; i++) {
    //     pi_x[i] = circ.addGate(GateType::kDotprod, M_pi[i], x);
        
    // }
    std::vector<wire_t> leveli(N);
    // leveli = std::move(pi_x);
    leveli = std::move(x);

    R neg_one = R(-1);
    R one = R(1);

    int bound = log(N)/log(2);
    
    // comparison
    for(int level = 1; level <= bound; level++) {
      std::vector<wire_t> level_next(N/pow(2,level));
      for(int i = 0; i < N/pow(2, level); i++) {
        auto temp1 = circ.addGate(GateType::kSub, leveli[2*i], leveli[2*i + 1]);
        auto temp2 = circ.addGate(GateType::kLtz, temp1);
        auto temp3 = circ.addConstOpGate(GateType::kConstMul, temp2, neg_one);
        auto temp4 = circ.addConstOpGate(GateType::kConstAdd, temp3, one);
        auto temp5 = circ.addGate(GateType::kMul, temp4, temp1);
        level_next[i] = circ.addGate(GateType::kAdd, temp5, leveli[2*i + 1]);
      }
      leveli.resize(N/pow(2,level));
      leveli = std::move(level_next);
    }
    circ.setAsOutput(leveli[0]);
    return circ;
  }

  static Circuit generateCDA(int M, int N) {
    Circuit circ;
    return circ;
  }
};
};  // namespace common::utils
