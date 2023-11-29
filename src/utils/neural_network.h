#pragma once

#include <boost/multi_array.hpp>
#include <stdexcept>

#include "types.h"
#include "circuit.h"

namespace common::utils {
using wmat2_t = boost::multi_array<wire_t, 2>;
using wmat3_t = boost::multi_array<wire_t, 3>;
using wmat4_t = boost::multi_array<wire_t, 4>;
using range = boost::multi_array_types::index_range;

template <typename R>
class NeuralNetwork {
  Circuit<R> circ_;
  std::vector<wmat2_t> linear_weights_;
  std::vector<wmat4_t> conv_weights_;
  std::vector<wmat3_t> conv_bias_;

 public:
  NeuralNetwork() = default;

  template <size_t N>
  boost::multi_array<wire_t, N> newInput(std::array<size_t, N> shape) {
    boost::multi_array<wire_t, N> mat(shape);
    auto* it = mat.origin();
    auto* end = mat.origin() + mat.num_elements();
    for (; it != end; ++it) {
      *it = circ_.newInputWire();
    }

    return mat;
  }

  // Fully connected layer.
  //
  // 'input' is matrix of order (N, a).
  // Output is matrix of the form (N, out_dim).
  wmat2_t linear(const wmat2_t& input, size_t out_dim) {
    auto inp_shape = input.shape();

    wmat2_t weights = newInput<2>({out_dim, inp_shape[1] + 1});
    std::array<size_t, 2> out_shape = {inp_shape[0], out_dim};
    wmat2_t output(out_shape);

    for (size_t b = 0; b < inp_shape[0]; ++b) {
      std::vector<wire_t> vinp(input[b].begin(), input[b].end());

      size_t bias_idx = inp_shape[1];
      for (int i = 0; i < out_dim; ++i) {
        std::vector<wire_t> vwt(weights[i].begin(),
                                weights[i].begin() + bias_idx);
        auto wdotp = circ_.addGate(GateType::kTrdotp, vwt, vinp);
        output[b][i] =
            circ_.addGate(GateType::kAdd, wdotp, weights[i][bias_idx]);
      }
    }

    linear_weights_.push_back(std::move(weights));
    return output;
  }

  [[nodiscard]] const wmat2_t& getLinearWeights(size_t idx) const {
    return linear_weights_.at(idx);
  }

  template <size_t N>
  boost::multi_array<wire_t, N> relu(
      const boost::multi_array<wire_t, N>& input) {
    auto inp_shape = input.shape();
    std::array<size_t, N> out_shape;
    for (size_t i = 0; i < N; ++i) {
      out_shape[i] = inp_shape[i];
    }

    boost::multi_array<wire_t, N> output(out_shape);

    auto* out_it = output.origin();
    const auto* inp_it = input.origin();
    for (size_t i = 0; i < output.num_elements(); ++i) {
      *out_it = circ_.addGate(GateType::kRelu, *inp_it);
      out_it++;
      inp_it++;
    }

    return output;
  }

  wmat4_t convolution(const wmat4_t& input, std::array<size_t, 2> kernel_shape,
                      size_t num_filters, bool padding) {
    auto inp_shape = input.shape();

    auto out_h = inp_shape[1] - kernel_shape[0] + 1;
    auto out_w = inp_shape[2] - kernel_shape[1] + 1;
    if (padding) {
      out_h = inp_shape[1];
      out_w = inp_shape[2];
    }
    std::array<size_t, 4> out_shape = {inp_shape[0], out_h, out_w, num_filters};
    wmat4_t output(out_shape);

    wmat4_t weights = newInput<4>(
        {num_filters, kernel_shape[0], kernel_shape[1], inp_shape[3]});
    wmat3_t bias = newInput<3>({out_h, out_w, num_filters});

    size_t inp_st_h = 0;
    size_t inp_st_w = 0;
    size_t inp_ed_h = 0;
    size_t inp_ed_w = 0;
    if (padding) {
      inp_st_h = (kernel_shape[0] - 1) / 2;
      inp_st_w = (kernel_shape[1] - 1) / 2;
      inp_ed_h = inp_st_h + inp_shape[1];
      inp_ed_w = inp_st_w + inp_shape[2];
    }

    for (size_t b = 0; b < out_shape[0]; ++b) {
      for (size_t d = 0; d < out_shape[3]; ++d) {
        auto kernel = weights[d];
        for (size_t i = 0; i < out_shape[1]; ++i) {
          for (size_t j = 0; j < out_shape[2]; ++j) {
            // Compute convolution/dot-product inputs for output[i][j][d].
            std::vector<wire_t> vwt;
            std::vector<wire_t> vinp;
            for (size_t kd = 0; kd < inp_shape[3]; ++kd) {
              for (size_t ki = 0; ki < kernel_shape[0]; ++ki) {
                for (size_t kj = 0; kj < kernel_shape[1]; ++kj) {
                  if (padding) {
                    auto idx_h = i + ki;
                    auto idx_w = j + kj;
                    if (idx_h >= inp_st_h && idx_w >= inp_st_w &&
                        idx_h < inp_ed_h && idx_w < inp_ed_w) {
                      idx_h -= inp_st_h;
                      idx_w -= inp_st_w;
                      vwt.push_back(kernel[ki][kj][kd]);
                      vinp.push_back(input[b][idx_h][idx_w][kd]);
                    }
                  } else {
                    vwt.push_back(kernel[ki][kj][kd]);
                    vinp.push_back(input[b][i + ki][j + kj][kd]);
                  }
                }
              }
            }

            auto wdotp = circ_.addGate(GateType::kTrdotp, vwt, vinp);
            output[b][i][j][d] =
                circ_.addGate(GateType::kAdd, wdotp, bias[i][j][d]);
          }
        }
      }
    }

    conv_weights_.push_back(std::move(weights));
    conv_bias_.push_back(std::move(bias));

    return output;
  }

  wmat4_t averagePool(const wmat4_t& input, std::array<size_t, 2> pool_shape,
                      std::array<size_t, 2> strides) {
    auto inp_shape = input.shape();

    std::array<size_t, 4> out_shape = {
        inp_shape[0], (inp_shape[1] - pool_shape[0]) / strides[0] + 1,
        (inp_shape[2] - pool_shape[1]) / strides[1] + 1, inp_shape[3]};
    wmat4_t output(out_shape);

    double div = 1.0 / (1.0 * pool_shape[0] * pool_shape[1]);
    Ring multiplier = 1UL << FRACTION;
    div *= multiplier;
    Ring rdiv = static_cast<Ring>(div);

    for (size_t b = 0; b < out_shape[0]; ++b) {
      for (size_t d = 0; d < out_shape[3]; ++d) {
        for (size_t i = 0; i < out_shape[1]; ++i) {
          for (size_t j = 0; j < out_shape[2]; ++j) {
            // Compute average.
            wire_t acc{};
            for (size_t pi = 0; pi < pool_shape[0]; ++pi) {
              for (size_t pj = 0; pj < pool_shape[1]; ++pj) {
                if (pi == 0 && pj == 0) {
                  acc = input[b][i * strides[0] + pi][j * strides[1] + pj][d];
                } else {
                  auto winp =
                      input[b][i * strides[0] + pi][j * strides[1] + pj][d];
                  acc = circ_.addGate(GateType::kAdd, acc, winp);
                }
              }
            }
            output[b][i][j][d] =
                circ_.addConstOpGate(GateType::kConstMul, acc, rdiv);
          }
        }
      }
    }

    return output;
  }

  template <size_t N>
  wmat2_t flatten(const boost::multi_array<wire_t, N>& input) {
    auto inp_shape = input.shape();

    size_t total = 1;
    for (size_t i = 1; i < N; ++i) {
      total *= inp_shape[i];
    }

    std::array<size_t, 2> out_shape = {inp_shape[0], total};
    wmat2_t output(out_shape);

    auto* out_it = output.origin();
    const auto* inp_it = input.origin();
    for (size_t i = 0; i < output.num_elements(); ++i) {
      *out_it = *inp_it;
      out_it++;
      inp_it++;
    }

    return output;
  }

  template <size_t N>
  void setOutput(const boost::multi_array<wire_t, N>& input) {
    const auto* inp_it = input.origin();
    for (size_t i = 0; i < input.num_elements(); ++i, ++inp_it) {
      circ_.setAsOutput(*inp_it);
    }
  }

  const Circuit<R>& getCircuit() { return circ_; }

  static NeuralNetwork<R> fcnMNIST(size_t batch_size) {
    NeuralNetwork<R> nn;
    auto input = nn.newInput<2>({batch_size, 28 * 28});

    auto layer1_lin = nn.linear(input, 128);
    auto layer1_out = nn.relu(layer1_lin);

    auto layer2_lin = nn.linear(layer1_out, 128);
    auto layer2_out = nn.relu(layer2_lin);

    auto output = nn.linear(layer2_out, 10);
    nn.setOutput(output);

    return std::move(nn);
  }

  static NeuralNetwork<R> lenetMNIST(size_t batch_size) {
    NeuralNetwork<R> nn;
    auto input = nn.newInput<4>({batch_size, 28, 28, 1});

    auto layer1_conv = nn.convolution(input, {5, 5}, 20, false);
    auto layer1_relu = nn.relu(layer1_conv);
    auto layer1_out = nn.averagePool(layer1_relu, {2, 2}, {2, 2});

    auto layer2_conv = nn.convolution(layer1_out, {5, 5}, 50, false);
    auto layer2_relu = nn.relu(layer2_conv);
    auto layer2_out = nn.averagePool(layer2_relu, {2, 2}, {2, 2});

    auto layer2_flat = nn.flatten(layer2_out);

    auto layer3_lin = nn.linear(layer2_flat, 500);
    auto layer3_out = nn.relu(layer3_lin);

    auto output = nn.linear(layer3_out, 10);
    nn.setOutput(output);

    return std::move(nn);
  }
};
}  // namespace common::utils
