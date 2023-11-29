#define BOOST_TEST_MODULE io
#include <io/netmp.h>

#include <boost/test/included/unit_test.hpp>
#include <future>
#include <random>
#include <vector>

BOOST_AUTO_TEST_SUITE(netmp)

BOOST_AUTO_TEST_CASE(echo_2P) {
  std::string message("A test string.");

  auto party = std::async(std::launch::async, [=]() {
    io::NetIOMP net(1, 2, 10000, nullptr, true);
    std::vector<uint8_t> data(message.size());
    net.recv(0, data.data(), data.size());
    net.send(0, data.data(), data.size());
  });

  io::NetIOMP net(0, 2, 10000, nullptr, true);
  net.send(1, message.data(), message.size());

  std::vector<uint8_t> received_message(message.size());
  net.recv(1, received_message.data(), received_message.size());

  party.wait();

  BOOST_TEST(received_message ==
             std::vector<uint8_t>(message.begin(), message.end()));
}

BOOST_AUTO_TEST_CASE(mssg_pass_4P) {
  std::string message("A test string.");

  std::vector<std::future<void>> parties;
  for (size_t i = 1; i < 4; ++i) {
    parties.push_back(std::async(std::launch::async, [=]() {
      io::NetIOMP net(i, 4, 10000, nullptr, true);
      std::vector<uint8_t> data(message.size());
      net.recvRelative(-1, data.data(), data.size());
      net.sendRelative(1, data.data(), data.size());
      net.flush();
    }));
  }

  io::NetIOMP net(0, 4, 10000, nullptr, true);
  net.sendRelative(1, message.data(), message.size());
  net.flush();

  std::vector<uint8_t> received_message(message.size());
  net.recvRelative(-1, received_message.data(), received_message.size());

  for (auto& p : parties) {
    p.wait();
  }

  BOOST_TEST(received_message ==
             std::vector<uint8_t>(message.begin(), message.end()));
}

BOOST_AUTO_TEST_CASE(echo_bool) {
  const size_t len = 65;

  std::mt19937 gen(200);
  std::bernoulli_distribution distrib;

  bool message[len];
  for (bool& i : message) {
    i = distrib(gen);
  }

  auto party = std::async(std::launch::async, [=]() {
    io::NetIOMP net(1, 2, 10000, nullptr, true);
    bool data[len];
    net.recvBool(0, static_cast<bool*>(data), len);
    net.sendBool(0, static_cast<bool*>(data), len);
  });

  io::NetIOMP net(0, 2, 10000, nullptr, true);
  net.sendBool(1, static_cast<bool*>(message), len);

  bool received_message[len];
  net.recvBool(1, static_cast<bool*>(received_message), len);

  party.wait();

  for (size_t i = 0; i < len; ++i) {
    BOOST_TEST(received_message[i] == message[i]);
  }
}

BOOST_AUTO_TEST_SUITE_END()
