// Control Plane Epoch 1.0.0 - Summon Software Labs
// Test entry point. The runner accepts --filter=<substring> and
// --skip=<substring>; no timeout option exists and none is honoured.
#include <exception>
#include <iostream>
#include <string>

#include "test_harness.hpp"

int main(int argc, char** argv) {
  std::string filter;
  std::string skip;
  for (int index = 1; index < argc; ++index) {
    const std::string argument(argv[index]);
    constexpr const char* kFilterPrefix = "--filter=";
    constexpr const char* kSkipPrefix = "--skip=";
    if (argument.rfind(kFilterPrefix, 0) == 0) {
      filter = argument.substr(std::string(kFilterPrefix).size());
    } else if (argument.rfind(kSkipPrefix, 0) == 0) {
      skip = argument.substr(std::string(kSkipPrefix).size());
    } else {
      std::cerr << "usage: " << argv[0] << " [--filter=SUBSTRING] [--skip=SUBSTRING]\n";
      return 2;
    }
  }
  try {
    return cpe_test::run_all(filter, skip);
  } catch (const std::exception& error) {
    std::cerr << "the test runner itself failed: " << error.what() << '\n';
    return 1;
  }
}
