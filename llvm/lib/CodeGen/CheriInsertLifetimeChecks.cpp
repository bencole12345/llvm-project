#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Target/TargetMachine.h"

#include <string>

#define DEBUG_TYPE "cheri-insert-lifetime-checks"
#define PASS_NAME "Insert lifetime checks pass"

using namespace llvm;

namespace {

// TODO: Add some statistics

/**
 * Inserts lifetime checks to ensure temporal stack safety.
 */
class CheriInsertLifetimeChecks : public ModulePass {
public:
  static char ID;
  CheriInsertLifetimeChecks();
  StringRef getPassName() const override;
  bool runOnModule(Module &Mod) override;

private:
  bool runOnFunction(Function &F, Module *M) const;

  /// Inserts a stack lifetime check directly before a pointer-type store
  /// instruction.
  void insertCheckBefore(StoreInst &I, Module *M) const;
};

} // anonymous namespace

CheriInsertLifetimeChecks::CheriInsertLifetimeChecks() : ModulePass(ID) {
  initializeCheriInsertLifetimeChecksPass(*PassRegistry::getPassRegistry());
}

StringRef CheriInsertLifetimeChecks::getPassName() const {
  return PASS_NAME;
}

bool CheriInsertLifetimeChecks::runOnModule(Module &Mod) {
  bool modified = false;
  for (Function &F : Mod) {
    modified |= runOnFunction(F, &Mod);
  }
  return modified;
}

bool CheriInsertLifetimeChecks::runOnFunction(Function &F, Module *M) const {

  // Insert check instructions before all pointer-type stores
  bool ContainsChecks = false;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (I.getOpcode() != Instruction::Store || !isa<StoreInst>(I))
        continue;
      auto &Store = cast<StoreInst>(I);
      if (!Store.getValueOperand()->getType()->isPointerTy())
        continue;

      // Now we're definitely looking at a pointer-type store
      insertCheckBefore(Store, M);
      ContainsChecks = true;
    }
  }

  return ContainsChecks;
}

void CheriInsertLifetimeChecks::insertCheckBefore(StoreInst &I,
                                                  Module *M) const {
  assert(I.getValueOperand()->getType()->isPointerTy());

  LLVMContext &Context = I.getContext();
  DataLayout DL(M);

  // Address spaces of the cap used to store and the cap being stored
  // unsigned PointerAS = getLoadStoreAddressSpace(&I);
  unsigned ValueAS = I.getValueOperand()->getType()->getPointerAddressSpace();

  // Types of the pointers and offsets
  Type *SizeTy = Type::getIntNTy(Context, DL.getIndexSizeInBits(ValueAS));

  // Insert the ccsc instruction
  IRBuilder<> Builder(&I);
  // TODO: Handle offsets correctly (currently the arguments come from different
  // capabilities if a getelementptr instruction is used)
  Builder.CreateIntrinsic(Intrinsic::cheri_check_cap_store_cap,
                          {I.getValueOperand()->getType(),
                           I.getPointerOperand()->getType(), SizeTy},
                          {I.getValueOperand(), I.getPointerOperand(),
                           ConstantInt::get(SizeTy, 0)});
}

char CheriInsertLifetimeChecks::ID;
INITIALIZE_PASS(CheriInsertLifetimeChecks, DEBUG_TYPE,
                "CHERI insert lifetime checks to store instructions", false,
                false)

ModulePass *llvm::createCheriInsertLifetimeChecksPass() {
  return new CheriInsertLifetimeChecks();
}
