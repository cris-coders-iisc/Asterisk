#include "utils.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pE.h>

#include <fstream>
#include <iostream>

TimePoint::TimePoint() : time(timepoint_t::clock::now()) {}

double TimePoint::operator-(const TimePoint& rhs) const {
  return std::chrono::duration_cast<timeunit_t>(time - rhs.time).count();
}

CommPoint::CommPoint(io::NetIOMP& network) : stats(network.nP) {
  for (size_t i = 0; i < network.nP; ++i) {
    if (i != network.party) {
      stats[i] = network.get(i, false)->counter + network.get(i, true)->counter;
    }
  }
}

std::vector<uint64_t> CommPoint::operator-(const CommPoint& rhs) const {
  std::vector<uint64_t> res(stats.size());
  for (size_t i = 0; i < stats.size(); ++i) {
    res[i] = stats[i] - rhs.stats[i];
  }
  return res;
}

StatsPoint::StatsPoint(io::NetIOMP& network) : cpoint_(network) {}

nlohmann::json StatsPoint::operator-(const StatsPoint& rhs) {
  return {{"time", tpoint_ - rhs.tpoint_},
          {"communication", cpoint_ - rhs.cpoint_}};
}

bool saveJson(const nlohmann::json& data, const std::string& fpath) {
  std::ofstream fout;
  //fout.open(fpath, std::fstream::out);
  fout.open(fpath, std::fstream::app);
  if (!fout.is_open()) {
    std::cerr << "Could not open save file at " << fpath << "\n";
    return false;
  }

  fout << data;
  fout << std::endl;
  fout.close();

  std::cout << "Saved data in " << fpath << std::endl;

  return true;
}

void initNTL(size_t num_threads) {
  NTL::ZZ_p::init(NTL::conv<NTL::ZZ>("18446744073709551616"));
  NTL::ZZ_pX P(NTL::INIT_MONO, 47);
  NTL::SetCoeff(P, 5);
  NTL::SetCoeff(P, 0);
  NTL::ZZ_pE::init(P);

  NTL::SetNumThreads(num_threads);
}

#ifdef __APPLE__

#include <mach/mach.h>

int64_t peakResidentSetSize() {
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;

  kern_return_t ret = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                reinterpret_cast<task_info_t>(&info), &count);
  if (ret != KERN_SUCCESS || count != MACH_TASK_BASIC_INFO_COUNT) {
    return -1;
  }

  return info.resident_size_max;
}

int64_t peakVirtualMemory() {
  // No way to get peak virtual memory usage on OSX.
  return peakResidentSetSize();
}
#elif __linux__
// Reference: https://gist.github.com/k3vur/4169316
int64_t getProcStatus(const std::string& key) {
  int64_t value = 0;

  const char* filename = "/proc/self/status";

  std::ifstream procfile(filename);
  std::string word;
  while (procfile.good()) {
    procfile >> word;
    if (word == key) {
      procfile >> value;
      break;
    }

    // Skip to end of line.
    procfile.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  }

  if (procfile.fail()) {
    return -1;
  }

  return value;
}

int64_t peakVirtualMemory() { return getProcStatus("VmPeak:"); }

int64_t peakResidentSetSize() { return getProcStatus("VmHWM:"); }
#else
int64_t peakVirtualMemory() { return -1; }

int64_t peakResidentSetSize() { return -1; }
#endif
