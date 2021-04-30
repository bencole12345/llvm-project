#include "RISCV.h"

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"

using namespace llvm;

#define RISCV_REVOCATION_LOWERING_NAME "RISCV revocation lowering"

namespace {

class RISCVRevocationLowering : public MachineFunctionPass {
public:
  static char ID;

  RISCVRevocationLowering() : MachineFunctionPass(ID) {
    initializeRISCVRevocationLoweringPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override {
    return RISCV_REVOCATION_LOWERING_NAME;
  }
};

char RISCVRevocationLowering::ID = 0;

bool RISCVRevocationLowering::runOnMachineFunction(MachineFunction &MF) {
  // TODO: Implement

  bool Changed = false;

  errs() << "Running on machine function: " << MF.getName() << "\n";

  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      // MI.get
      // if ()
      if (MI.isCall()) {
        MI.dump();
      }
    }
  }

  return Changed;
}

} // anonymous namespace

INITIALIZE_PASS(RISCVRevocationLowering, "riscv-revocation-lowering",
                RISCV_REVOCATION_LOWERING_NAME, false, false)

namespace llvm {

FunctionPass *createRISCVRevocationLoweringPass() {
  return new RISCVRevocationLowering();
}

} // namespace llvm
