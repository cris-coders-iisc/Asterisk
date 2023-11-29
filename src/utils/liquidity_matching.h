#pragma once

#include <boost/multi_array.hpp>
#include <filesystem>
#include <stdexcept>
#include <unordered_map>

#include "types.h"
#include "circuit.h"

namespace common::utils {

// Source-open Destination-open Transaction
struct SoDoTxn {
  unsigned int src;
  unsigned int dest;
  wire_t amt;

  SoDoTxn() = default;
  SoDoTxn(unsigned int src, unsigned int dest, wire_t amt)
      : src{src}, dest{dest}, amt{amt} {}
};

// TODO: Extend implementation to support multiple iterations of GridLock.
// Might require extending core MPC implementation.
template <typename R>
class SoDoGridLock {
  Circuit<R> circ_;
  std::vector<SoDoTxn> txn_queue_;
  size_t num_banks_;

 public:
  explicit SoDoGridLock(size_t num_banks) : num_banks_{num_banks} {}

  wire_t newTransaction(unsigned int src, unsigned int dest) {
    if (src >= num_banks_ || dest >= num_banks_) {
      throw std::invalid_argument(
          "Source and destination ids are zero indexed.");
    }

    auto amt = circ_.newInputWire();
    txn_queue_.emplace_back(src, dest, amt);
    return amt;
  }

  wire_t treeMult(const std::vector<wire_t>& inputs) {
    auto prev_level = inputs;

    while (prev_level.size() != 1) {
      std::vector<wire_t> curr_level;

      for (size_t i = 0; i < prev_level.size() - 1; i += 2) {
        curr_level.push_back(
            circ_.addGate(GateType::kMul, prev_level[i], prev_level[i + 1]));
      }
      if (prev_level.size() % 2 == 1) {
        curr_level.push_back(prev_level.back());
      }
      prev_level = std::move(curr_level);
    }

    return prev_level[0];
  }

  // Length of 'balance' is equal to the number of banks and corresponds to
  // balance of each bank.
  // Length of 'selected' is equal to the length of 'txn_queue_' and
  // it corresponds to an indicator vector for the set of selected
  // transactions.
  std::vector<wire_t> newBalances(std::vector<wire_t> balance,
                                  std::vector<wire_t> selected) {
    std::vector<wire_t> filter_txn_amt(txn_queue_.size());
    for (size_t i = 0; i < txn_queue_.size(); i++) {
      filter_txn_amt[i] =
          circ_.addGate(GateType::kMul, selected[i], txn_queue_[i].amt);
    }

    // 'wire_t' is unsigned and we're using -1 to denote empty values.
    // Probably more robust to use boolean flags instead.
    std::vector<wire_t> vs(num_banks_, -1);
    std::vector<wire_t> vr(num_banks_, -1);

    for (size_t i = 0; i < txn_queue_.size(); i++) {
      const auto& txn = txn_queue_[i];

      if (vs[txn.src] == -1) {
        vs[txn.src] = filter_txn_amt[i];
      } else {
        vs[txn.src] =
            circ_.addGate(GateType::kAdd, vs[txn.src], filter_txn_amt[i]);
      }

      if (vr[txn.dest] == -1) {
        vr[txn.dest] = filter_txn_amt[i];
      } else {
        vr[txn.dest] =
            circ_.addGate(GateType::kAdd, vr[txn.dest], filter_txn_amt[i]);
      }
    }

    std::vector<wire_t> new_balance(num_banks_);
    for (size_t i = 0; i < num_banks_; i++) {
      new_balance[i] = balance[i];
      if (vs[i] != -1) {
        new_balance[i] = circ_.addGate(GateType::kSub, new_balance[i], vs[i]);
      }
      if (vr[i] != -1) {
        new_balance[i] = circ_.addGate(GateType::kAdd, new_balance[i], vr[i]);
      }
    }

    return new_balance;
  }

  // Corresponds to a single iteration of the gridlock algorithm.
  std::vector<wire_t> updateSelectedTransactions(std::vector<wire_t> balance,
                                                 std::vector<wire_t> selected) {
    auto new_balance = newBalances(balance, selected);
    std::vector<wire_t> is_negative_balance(num_banks_);
    for (size_t i = 0; i < num_banks_; i++) {
      is_negative_balance[i] = circ_.addGate(GateType::kMsb, new_balance[i]);
    }

    std::vector<wire_t> is_positive_balance(num_banks_);
    for (size_t i = 0; i < num_banks_; i++) {
      is_positive_balance[i] = circ_.addConstOpGate(
          GateType::kConstMul, is_negative_balance[i], static_cast<R>(-1));
      is_positive_balance[i] = circ_.addConstOpGate(
          GateType::kConstAdd, is_positive_balance[i], static_cast<R>(1));
    }

    // Tree mult.
    auto all_balances_positive = treeMult(is_positive_balance);

    // TODO: Reconstruct secret on all_balances_positive and check if it is 1.
    // Assuming all_balances_positive != 1 and proceeding with iteration.
    circ_.setAsOutput(all_balances_positive);

    std::vector<std::vector<size_t>> txn_by_src(num_banks_);
    for (size_t i = 0; i < txn_queue_.size(); i++) {
      txn_by_src[txn_queue_[i].src].push_back(i);
    }

    std::vector<wire_t> new_selected(txn_queue_.size());
    for (size_t i = 0; i < num_banks_; i++) {
      const auto& stxn = txn_by_src[i];

      for (size_t j = 0; !stxn.empty() && j < stxn.size() - 1; j++) {
        auto xprod = circ_.addGate(GateType::kMul, selected[stxn[j]],
                                   selected[stxn[j + 1]]);
        auto term1 =
            circ_.addGate(GateType::kMul, xprod, is_negative_balance[i]);
        auto term2 = circ_.addGate(GateType::kMul, selected[stxn[j]],
                                   is_positive_balance[i]);

        new_selected[stxn[j]] = circ_.addGate(GateType::kAdd, term1, term2);
      }

      if (!stxn.empty()) {
        auto txn_id = stxn.back();
        new_selected[txn_id] = circ_.addGate(GateType::kMul, selected[txn_id],
                                             is_positive_balance[i]);
      }
    }

    std::vector<wire_t> is_not_selected;
    for (auto w : new_selected) {
      auto wtemp =
          circ_.addConstOpGate(GateType::kConstMul, w, static_cast<R>(-1));
      is_not_selected.push_back(
          circ_.addConstOpGate(GateType::kConstAdd, wtemp, static_cast<R>(1)));
    }

    auto is_deadlock = treeMult(is_not_selected);
    circ_.setAsOutput(is_deadlock);

    return new_selected;
  }

  const Circuit<R>& getCircuit() { return circ_; }

  std::vector<wire_t> initBalances(const std::vector<R>& balances,
                                   std::unordered_map<wire_t, R>& imap) {
    std::vector<wire_t> output(num_banks_);
    for (size_t i = 0; i < num_banks_; i++) {
      output[i] = circ_.newInputWire();
      imap[output[i]] = balances[i];
    }

    return output;
  }

  std::vector<wire_t> initSelectedSet(std::unordered_map<wire_t, R>& imap) {
    std::vector<wire_t> output(txn_queue_.size());
    for (size_t i = 0; i < txn_queue_.size(); i++) {
      output[i] = circ_.newInputWire();
      imap[output[i]] = 1;
    }

    return output;
  }
};
}  // namespace common::utils
