#define BOOST_TEST_MODULE rand
#include <emp-tool/emp-tool.h>
#include <asterisk/rand_gen_pool.h>

#include <boost/test/data/monomorphic.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/included/unit_test.hpp>
#include <map>
#include <random>

using namespace asterisk;

namespace bdata = boost::unit_test::data;

constexpr int TEST_DATA_MAX_VAL = 1000;

BOOST_AUTO_TEST_SUITE(rand_gen_pool)

BOOST_AUTO_TEST_CASE(matching_output) {
    const int num_tests = 10;
    uint64_t seed = 200;
    int nP = 4;
    auto rpool_0 = asterisk::RandGenPool(0, nP+1, seed);
    uint64_t b0;
    
   for (int i = 1; i <= nP; ++i) {
        auto rpool_i = asterisk::RandGenPool(i, nP+1, seed);
        

        uint64_t bi;
        rpool_i.p0().random_data(&bi, sizeof(uint64_t));
        rpool_0.pi(i).random_data(&b0, sizeof(uint64_t));
        // CHECK WITH TP
        BOOST_TEST(bi == b0);

        // CHECK ALL
        rpool_i.all().random_data(&bi, sizeof(uint64_t));
        
        for(int j = 1; j < i; j++)  {
            auto rpool_j = asterisk::RandGenPool(j, nP+1, seed);
            uint64_t bj;
            rpool_j.all().random_data(&bj, sizeof(uint64_t));
            
            BOOST_TEST(bi == bj);
        }

        // CHECK ALL MINUS TP
        rpool_i.all_minus_0().random_data(&bi, sizeof(uint64_t));
        
        for(int j = 0; j < i; j++)  {
            auto rpool_j = asterisk::RandGenPool(j, nP+1, seed);
            uint64_t bj;
            rpool_j.all_minus_0().random_data(&bj, sizeof(uint64_t));
            // CHECK ALL
            BOOST_TEST(bi == bj);
        }
    }
    
}

BOOST_AUTO_TEST_SUITE_END()
