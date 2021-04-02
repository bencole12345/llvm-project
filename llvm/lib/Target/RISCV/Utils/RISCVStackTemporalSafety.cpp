#include "RISCVStackTemporalSafety.h"

#include "llvm/Support/CommandLine.h"

namespace llvm {
namespace RISCVStackTemporalSafety {

namespace {

cl::opt<bool> EnableStackTemporalSafetyMitigations(
    "enable-stack-temporal-safety-mitigations",
    cl::desc("Enable mitigations to provide stack temporal memory safety"));
    // TODO: Add cl::init(false) as an extra argument?

} // anonymous namespace

bool stackTemporalSafetyMitigationsEnabled() {
  return EnableStackTemporalSafetyMitigations;
}

} // namespace RISCVStackTemporalSafety
} // namespace llvm
