#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
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
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#define DEBUG_TYPE "cheri-insert-lifetime-checks"
using namespace llvm;
#define DBG_MESSAGE(...) LLVM_DEBUG(dbgs() << DEBUG_TYPE ": " << __VA_ARGS__)

namespace {

// TODO: Add some statistics

#define SHADOW_STACK_CAP_GLOBAL_NAME "StackShadowStackCap"

/**
 * Inserts lifetime checks to ensure temporal stack safety.
 */
class CheriInsertLifetimeChecks : public ModulePass {
private:
  FunctionCallee CapRevokeFunction;
  FunctionCallee CapRevokeShadowFunction;

public:
  static char ID;
  CheriInsertLifetimeChecks();
  StringRef getPassName() const override;
  bool runOnModule(Module &Mod) override;

private:
  bool runOnFunction(Function &F, Module *M,
                     GlobalVariable *ShadowStackPtr) const;

  /// Creates a global variable containing the shadow stack pointer and
  /// initialises it using a caprevoke_shadow() system call.
  void insertSetupShadowStackPointer(Function &F, Module *M,
                                     GlobalVariable *ShadowStackPtr) const;

  /// Inserts a stack lifetime check directly before a pointer-type store
  /// instruction.
  void insertCheckBefore(StoreInst &I, Module *M) const;

  /// Adds metadata to a function to indicate whether it contains any lifetime
  /// checks.
  void setContainsLifetimeChecksMetadata(Function &F,
                                         bool ContainsLifetimeChecks) const;

  /// Determines whether a basic block terminates with a return statement.
  bool blockIsReturnBlock(const BasicBlock &BB) const;

  /// Inserts code to perform a revocation sweep before the given Instruction.
  void insertTestAndRevokeBefore(Instruction &I, Module *M,
                                 GlobalVariable *ShadowStackPtr) const;
};

} // anonymous namespace

CheriInsertLifetimeChecks::CheriInsertLifetimeChecks() : ModulePass(ID) {
  initializeCheriInsertLifetimeChecksPass(*PassRegistry::getPassRegistry());
}

StringRef CheriInsertLifetimeChecks::getPassName() const {
  return "Insert lifetime checks pass";
}

bool CheriInsertLifetimeChecks::runOnModule(Module &Mod) {
  LLVMContext &Context = Mod.getContext();

  // Find the syscalls we need
  CapRevokeFunction =
      Mod.getOrInsertFunction("caprevoke", Type::getVoidTy(Mod.getContext()),
                              IntegerType::getInt8PtrTy(Mod.getContext()));
  CapRevokeShadowFunction = Mod.getOrInsertFunction(
      "caprevoke_shadow", IntegerType::getInt8PtrTy(Mod.getContext()));

  // TODO: Actually use the global
  // Create the global variable to hold the pointer to the stack's subset of the
  // shadow map
  Type *CharPtrTy = IntegerType::getInt8PtrTy(Context);
  // GlobalVariable *ShadowStackPtr = (GlobalVariable *)Mod.getOrInsertGlobal(
  //     SHADOW_STACK_CAP_GLOBAL_NAME, CharPtrTy);
  // ShadowStackPtr->setAlignment(Align(16));
  GlobalVariable *ShadowStackPtr = nullptr;

  // ShadowStackPtr->setLinkage(GlobalVariable::CommonLinkage);
  // ShadowStackPtr->setUnnamedAddr(GlobalVariable::UnnamedAddr::Global);

  // Run on each function
  bool modified = false;
  for (Function &F : Mod) {
    errs() << "Running on function: " << F.getName() << "\n";
    modified |= runOnFunction(F, &Mod, ShadowStackPtr);
  }

  return modified;
}

bool CheriInsertLifetimeChecks::runOnFunction(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  bool ContainsChecks = false;

  // Insert check instructions before all pointer-type stores
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (I.getOpcode() != Instruction::Store || !isa<StoreInst>(I))
        continue;
      auto &Store = cast<StoreInst>(I);
      if (!Store.getValueOperand()->getType()->isPointerTy())
        continue;
      insertCheckBefore(Store, M);
      ContainsChecks = true;
    }
  }

  // We need to use caprevoke_shadow() to get a capability to the subset of the
  // shadow map that corresponds to the stack. We do this at the start of the
  // main function.
  // TODO: Uncomment
  // if (F.getName().equals("main"))
  //   insertSetupShadowStackPointer(F, M, ShadowStackPtr);

  // If required, insert a test for revocation for all terminating basic blocks
  if (F.possiblyContainsEscapingLocals()) {
    /**
     * Inserting a revocation call requires splitting a basic block into
     * instructions before the return statement, and a new block containing just
     * the return statement. If we just naively loop over all return blocks then
     * we get stuck in an infinite loop until we run out of memory!
     */
    SmallVector<BasicBlock *, 16> TerminatingBlocks;
    for (BasicBlock &BB : F) {
      if (blockIsReturnBlock(BB))
        TerminatingBlocks.push_back(&BB);
    }
    assert(!TerminatingBlocks.empty());
    for (BasicBlock *BB : TerminatingBlocks) {
      auto &ReturnStatement = BB->back();
      insertTestAndRevokeBefore(ReturnStatement, M, ShadowStackPtr);
    }
  }

  return ContainsChecks;
}

void CheriInsertLifetimeChecks::insertSetupShadowStackPointer(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  LLVMContext &Context = M->getContext();

  // Find the first instruction
  BasicBlock &EntryBlock = F.getEntryBlock();
  Instruction &FirstInstruction = EntryBlock.getInstList().front();

  // Place a call to caprevoke_shadow() before it and store the result to the
  // global
  IRBuilder<> Builder(&FirstInstruction);
  CallInst *Call = Builder.CreateCall(CapRevokeShadowFunction);
  Builder.CreateStore(Call, ShadowStackPtr);
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

bool CheriInsertLifetimeChecks::blockIsReturnBlock(const BasicBlock &BB) const {
  return !BB.empty() && BB.back().getOpcode() == Instruction::Ret;
}

void CheriInsertLifetimeChecks::insertTestAndRevokeBefore(
    Instruction &I, Module *M, GlobalVariable *ShadowStackPtr) const {
  LLVMContext &Context = M->getContext();

  // TODO: Determine this properly
  IRBuilder<> Builder(&I);
  Value *Cond = Builder.CreateIntrinsic(
      Intrinsic::cheri_determine_stack_frame_revocation_required, {}, {});

  // If needed, branch to a new basic block containing the revocation call
  Instruction *NewTerminator = SplitBlockAndInsertIfThen(Cond, &I, false);
  Builder.SetInsertPoint(NewTerminator);

  // TODO: Remove
  CallInst *Call = Builder.CreateCall(CapRevokeShadowFunction);
  Builder.CreateCall(CapRevokeFunction, {Call});

  // TODO: Uncomment
  // Builder.CreateCall(CapRevokeFunction, {});
}

char CheriInsertLifetimeChecks::ID;
INITIALIZE_PASS(CheriInsertLifetimeChecks, DEBUG_TYPE,
                "CHERI insert lifetime checks to store instructions", false,
                false)

ModulePass *llvm::createCheriInsertLifetimeChecksPass() {
  return new CheriInsertLifetimeChecks();
}
