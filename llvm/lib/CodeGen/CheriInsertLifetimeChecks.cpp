#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Target/TargetMachine.h"

#define DEBUG_TYPE "cheri-insert-lifetime-checks"
using namespace llvm;
#define DBG_MESSAGE(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE ": " << __VA_ARGS__)

namespace {

// // Command-line option to disable the check
// static cl::opt<bool> DisableLifetimeChecks(
//     "cheri-disable-stack-lifetime-checks", cl::init(false),
//     cl::desc("Disable insertion of lifetime checks for capability stores"));

/**
 * Inserts lifetime checks to ensure temporal stack safety.
 */
class CheriInsertLifetimeChecks : public ModulePass {
public:
  static char ID;
  CheriInsertLifetimeChecks();
  StringRef getPassName() const override;
  bool runOnModule(Module &Mod) override;
  virtual void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
  bool runOnFunction(Function &F, Module *M);
  void insertCheckBefore(StoreInst &I, Module *M);
};

CheriInsertLifetimeChecks::CheriInsertLifetimeChecks() : ModulePass(ID) {
  initializeCheriInsertLifetimeChecksPass(*PassRegistry::getPassRegistry());
}

StringRef CheriInsertLifetimeChecks::getPassName() const {
  return "Insert lifetime checks pass";
}

bool CheriInsertLifetimeChecks::runOnModule(Module &Mod) {
  // For now, just run on each function
  bool modified = false;
  for (Function &F : Mod) {

    // Dirty hack; will have to sort something better
    // if (F.getName() == "main")
    //   continue;

    modified |= runOnFunction(F, &Mod);
  }
  return modified;
}

void CheriInsertLifetimeChecks::getAnalysisUsage(AnalysisUsage &AU) const {
  // TODO: Add escape analysis pass once that's done
  return;
}

bool CheriInsertLifetimeChecks::runOnFunction(Function &F, Module *M) {
  bool modified = false;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {

      // We only want to analyse store instructions
      if (I.getOpcode() != Instruction::Store)
        continue;
      if (!isa<StoreInst>(I))
        continue;
      auto &Store = cast<StoreInst>(I);

      // We only care about stores of capabilities, not data
      if (!Store.getValueOperand()->getType()->isPointerTy())
        continue;

      insertCheckBefore(Store, M);
      modified = true;
    }
  }
  return modified;
}

void CheriInsertLifetimeChecks::insertCheckBefore(StoreInst &I, Module *M) {
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

} // anonymous namespace

char CheriInsertLifetimeChecks::ID;
INITIALIZE_PASS(CheriInsertLifetimeChecks, DEBUG_TYPE,
                "CHERI insert lifetime checks to store instructions", false,
                false)

ModulePass *llvm::createCheriInsertLifetimeChecksPass(void) {
  return new CheriInsertLifetimeChecks();
}
