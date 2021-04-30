// #include "llvm/CodeGen/Passes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/CHERICap.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

// TODO: Remove
#include "llvm/Support/ErrorHandling.h"

#define DEBUG_TYPE "cheri-insert-lifetime-checks"
using namespace llvm;
#define DBG_MESSAGE(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE ": " << __VA_ARGS__)

namespace llvm {
namespace cheri {
  // struct Temporal;
  extern char &TemporalID;
}
}


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
  virtual void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
  bool functionContainsEscapingValues(Function &F);
  bool runOnFunction(Function &F, Module *M);
  void insertCheckBefore(StoreInst &I, Module *M);
};

} // anonymous namespace

CheriInsertLifetimeChecks::CheriInsertLifetimeChecks() : ModulePass(ID) {
  // initializeCheriInsertLifetimeChecksPass(*PassRegistry::getPassRegistry());
}

StringRef CheriInsertLifetimeChecks::getPassName() const {
  return "Insert lifetime checks pass";
}

bool CheriInsertLifetimeChecks::runOnModule(Module &Mod) {
  // llvm_unreachable("CheriInsertLifetimeChecks running");
  bool modified = false;
  for (Function &F : Mod) {
    modified |= runOnFunction(F, &Mod);
  }
  return modified;
}

void CheriInsertLifetimeChecks::getAnalysisUsage(AnalysisUsage &AU) const {
  // TODO: Register dependence on escape analysis pass
  // AU.addRequired<cheri::Temporal>();
  // AU.addRequiredID(cheri::Temporal::ID);
  AU.addRequiredID(cheri::TemporalID);
  return;
}

bool CheriInsertLifetimeChecks::functionContainsEscapingValues(Function &F) {
  LLVMContext &Context = F.getContext();
  MDNode *analysis = F.getMetadata("containsEscapingLocals");
  assert(analysis && "Function must include temporal safety metadata");
  // Constant *val = dyn_cast<ConstantAsMetadata>(analysis->getOperand(0)->
  analysis->dump();
  // return true;
  return dyn_cast<MDString>(analysis->getOperand(0))->getString() == "safe";
}

bool CheriInsertLifetimeChecks::runOnFunction(Function &F, Module *M) {

  llvm_unreachable("Just testing that this thing actually runs");

  // TODO: Remove
  errs() << "Running on function: ";
  F.dump();

  // Don't do anything for non-escaping functions
  if (!functionContainsEscapingValues(F))
    return false;

  bool modified = false;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (I.getOpcode() != Instruction::Store)
        continue;
      if (!isa<StoreInst>(I))
        continue;

      auto &Store = cast<StoreInst>(I);
      if (!Store.getValueOperand()->getType()->isPointerTy())
        continue;

      // Now we're definitely looking at a pointer-type store

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

char CheriInsertLifetimeChecks::ID;
INITIALIZE_PASS(CheriInsertLifetimeChecks, DEBUG_TYPE,
                "CHERI insert lifetime checks to store instructions", false,
                false)

Pass *llvm::createCheriInsertLifetimeChecksPass(void) {
  return new CheriInsertLifetimeChecks();
}

// // TODO: See if I can remove this function
// // (Compiler says it's unused)
static void loadPass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
  PM.add(createCheriInsertLifetimeChecksPass());
}
