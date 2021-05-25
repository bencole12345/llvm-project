#include "llvm/ADT/SmallVector.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
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
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <string>

#define SHADOW_STACK_CAP_GLOBAL_NAME "StackShadowStackCap"

#define DEBUG_TYPE "cheri-cap-derived-lifetimes"
#define PASS_NAME "CHERI use capability-derived lifetimes"

using namespace llvm;

namespace {

// TODO: Add some statistics

cl::opt<bool> UnconditionalRevocationAfterAllFunctions(
    "unconditional-revoke-after-all-functions",
    cl::desc("Issue an unconditional revocation sweep after all functions"),
    cl::init(false));

cl::opt<bool> UnconditionalRevocationAfterAllEscapingFunctions(
    "unconditional-revoke-after-all-escaping-functions",
    cl::desc("Issue an unconditional revocation sweep after all functions"),
    cl::init(false));

/**
 * Denotes the conditions under which a function will need a revocation sweep
 * before it returns.
 */
enum class RevocationStrategy {

  /// No revocation required, this function is definitely safe.
  NoRevocation,

  /// This function includes lifetime checks, so we should test before any
  /// terminator whether any a StackLifetimeViolation exception happened and
  /// revoke if any did.
  ConditionalRevocation,

  /// This function should unconditionally have a revocation sweep before it
  /// terminates.
  UnconditionalRevocation
};

/**
 * Inserts lifetime checks to ensure temporal stack safety.
 */
class CheriCapDerivedLifetimes : public ModulePass {
private:
  FunctionCallee CaprevokeShadowFunction;
  FunctionCallee CaprevokeStackFunction;

public:
  static char ID;
  CheriCapDerivedLifetimes();
  StringRef getPassName() const override;
  bool runOnModule(Module &Mod) override;

private:
  /// Find the caprevoke_shadow() and caprevoke_stack() syscalls and set up the
  /// pointers to them.
  void initialiseCaprevokeFunctions(Module *M);

  /// Set up the global variable to store a capability to the relevant portion
  /// of the shadow stack.
  GlobalVariable *getShadowStackGlobalPtr(Module *M) const;

  /// Run the pass on a function.
  bool runOnFunction(Function &F, Module *M,
                     GlobalVariable *ShadowStackPtr) const;

  /// Inserts lifetime check instructions before all pointer-type stores.
  bool insertLifetimeChecks(Function &F, Module *M) const;

  /// Inserts a stack lifetime check directly before a pointer-type store
  /// instruction.
  void insertLifetimeCheckBefore(StoreInst &I, Module *M) const;

  /// Insert a call to caprevoke_shadow() to set up the global variable
  /// corresponding to the stack's portion of the shadow map.
  void insertCaprevokeInitialisation(Function &F, Module *M,
                                     GlobalVariable *ShadowStackPtr) const;

  /// Inserts a conditional revocation call before all terminators in the
  /// function.
  void insertConditionalRevocation(Function &F, Module *M,
                                   GlobalVariable *ShadowStackPtr) const;

  /// Inserts an unconditional revocation call before all terminators in the
  /// function.
  void insertUnconditionalRevocation(Function &F, Module *M,
                                     GlobalVariable *ShadowStackPtr) const;

  /// Determines whether a basic block terminates with a return statement.
  bool blockIsReturnBlock(const BasicBlock &BB) const;

  /// Insert a call to caprevoke_stack() using the supplied IRBuilder.
  void insertRevocationCall(IRBuilder<> &Builder, LLVMContext &Context,
                            GlobalVariable *ShadowStackPtr) const;

  /// Inserts code to perform a revocation sweep before the given Instruction.
  void insertTestAndRevokeBefore(Instruction &I, Module *M,
                                 GlobalVariable *ShadowStackPtr) const;

  /// Determines the revocation strategy for a function.
  RevocationStrategy getFunctionRevocationStrategy(const Function &F) const;

  /// Returns the frame pointer for the current function.
  Value *getFramePointer(LLVMContext &Context, IRBuilder<> &Builder) const;
};

} // anonymous namespace

CheriCapDerivedLifetimes::CheriCapDerivedLifetimes() : ModulePass(ID) {
  initializeCheriCapDerivedLifetimesPass(*PassRegistry::getPassRegistry());
}

StringRef CheriCapDerivedLifetimes::getPassName() const { return PASS_NAME; }

bool CheriCapDerivedLifetimes::runOnModule(Module &Mod) {
  initialiseCaprevokeFunctions(&Mod);
  GlobalVariable *ShadowStackPtr = getShadowStackGlobalPtr(&Mod);

  // Run on each function
  bool modified = false;
  for (Function &F : Mod) {
    modified |= runOnFunction(F, &Mod, ShadowStackPtr);
  }
  return modified;
}

void CheriCapDerivedLifetimes::initialiseCaprevokeFunctions(Module *M) {
  LLVMContext &Context = M->getContext();
  Type *VoidTy = Type::getVoidTy(Context);
  Type *CharPtrTy = IntegerType::getInt8PtrTy(Context);
  CaprevokeShadowFunction =
      M->getOrInsertFunction("caprevoke_shadow", VoidTy, CharPtrTy);
  CaprevokeStackFunction =
      M->getOrInsertFunction("caprevoke_stack", VoidTy, CharPtrTy, CharPtrTy);
}

GlobalVariable *
CheriCapDerivedLifetimes::getShadowStackGlobalPtr(Module *M) const {
  LLVMContext &Context = M->getContext();
  Type *CharPtrTy = IntegerType::getInt8PtrTy(Context);
  return (GlobalVariable *)M->getOrInsertGlobal(SHADOW_STACK_CAP_GLOBAL_NAME,
                                                CharPtrTy);
}

bool CheriCapDerivedLifetimes::runOnFunction(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  bool Changed = false;

  if (F.getName().equals("main")) {
    insertCaprevokeInitialisation(F, M, ShadowStackPtr);
    Changed = true;
  }

  // Insert CCSC instructions
  Changed |= insertLifetimeChecks(F, M);

  // Insert revocation calls at terminators
  switch (getFunctionRevocationStrategy(F)) {
  case RevocationStrategy::NoRevocation:
    break;
  case RevocationStrategy::ConditionalRevocation:
    Changed = true;
    insertConditionalRevocation(F, M, ShadowStackPtr);
    break;
  case RevocationStrategy::UnconditionalRevocation:
    Changed = true;
    insertUnconditionalRevocation(F, M, ShadowStackPtr);
  }

  return Changed;
}

bool CheriCapDerivedLifetimes::insertLifetimeChecks(Function &F,
                                                    Module *M) const {
  bool ContainsChecks = false;
  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (I.getOpcode() != Instruction::Store || !isa<StoreInst>(I))
        continue;
      auto &Store = cast<StoreInst>(I);
      if (!Store.getValueOperand()->getType()->isPointerTy())
        continue;

      // Now we're definitely looking at a pointer-type store
      insertLifetimeCheckBefore(Store, M);
      ContainsChecks = true;
    }
  }
  return ContainsChecks;
}

void CheriCapDerivedLifetimes::insertLifetimeCheckBefore(StoreInst &I,
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
  // TODO: Handle offsets correctly
  Builder.CreateIntrinsic(Intrinsic::cheri_check_cap_store_cap,
                          {I.getValueOperand()->getType(),
                           I.getPointerOperand()->getType(), SizeTy},
                          {I.getValueOperand(), I.getPointerOperand(),
                           ConstantInt::get(SizeTy, 0)});
}

void CheriCapDerivedLifetimes::insertCaprevokeInitialisation(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  LLVMContext &Context = M->getContext();

  BasicBlock &EntryBlock = F.getEntryBlock();
  Instruction &FirstInstruction = EntryBlock.front();

  IRBuilder<> Builder(&FirstInstruction);
  Value *FramePointer = getFramePointer(Context, Builder);
  CallInst *Call = Builder.CreateCall(CaprevokeShadowFunction, {FramePointer});
  Builder.CreateStore(Call, ShadowStackPtr);
}

void CheriCapDerivedLifetimes::insertConditionalRevocation(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  /*
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

void CheriCapDerivedLifetimes::insertUnconditionalRevocation(
    Function &F, Module *M, GlobalVariable *ShadowStackPtr) const {
  // See insertConditionalRevocation for explanation of double loop

  LLVMContext &Context = M->getContext();

  SmallVector<BasicBlock *, 16> TerminatingBlocks;
  for (BasicBlock &BB : F) {
    if (blockIsReturnBlock(BB))
      TerminatingBlocks.push_back(&BB);
  }
  assert(!TerminatingBlocks.empty());
  for (BasicBlock *BB : TerminatingBlocks) {
    auto &ReturnStatement = BB->back();
    IRBuilder<> Builder(&ReturnStatement);
    insertRevocationCall(Builder, Context, ShadowStackPtr);
  }
}

bool CheriCapDerivedLifetimes::blockIsReturnBlock(const BasicBlock &BB) const {
  return !BB.empty() && BB.back().getOpcode() == Instruction::Ret;
}

void CheriCapDerivedLifetimes::insertRevocationCall(
    IRBuilder<> &Builder, LLVMContext &Context,
    GlobalVariable *ShadowStackPtr) const {
  Value *FramePointer = getFramePointer(Context, Builder);
  Builder.CreateCall(CaprevokeStackFunction, {ShadowStackPtr, FramePointer});
}

void CheriCapDerivedLifetimes::insertTestAndRevokeBefore(
    Instruction &I, Module *M, GlobalVariable *ShadowStackPtr) const {
  LLVMContext &Context = M->getContext();
  Type *Int32Ty = IntegerType::getInt32Ty(Context);
  const unsigned VoidPtrAS = Type::getVoidTy(Context)->getPointerAddressSpace();
  Type *VoidPtrTy = Type::getVoidTy(Context)->getPointerTo(VoidPtrAS);
  IRBuilder<> Builder(&I);

  // Get the frame address
  Value *FramePointer = getFramePointer(Context, Builder);

  // Read the slot at the start of this frame to determine whether revocation is
  // required
  Value *StartOfFrame =
      Builder.CreateIntrinsic(Intrinsic::cheri_cap_get_frame_base,
                              {VoidPtrTy, VoidPtrTy}, {FramePointer});
  Value *RevocationRequired =
      Builder.CreateLoad(Int32Ty, StartOfFrame, "revocationRequired");

  // Add a conditional revocation
  Instruction *NewTerminator =
      SplitBlockAndInsertIfThen(RevocationRequired, &I, false);
  Builder.SetInsertPoint(NewTerminator);
  insertRevocationCall(Builder, Context, ShadowStackPtr);
}

RevocationStrategy CheriCapDerivedLifetimes::getFunctionRevocationStrategy(
    const Function &F) const {
  if (UnconditionalRevocationAfterAllFunctions)
    return RevocationStrategy::UnconditionalRevocation;
  if (UnconditionalRevocationAfterAllEscapingFunctions)
    return F.containsPossiblyEscapingLocals()
               ? RevocationStrategy::UnconditionalRevocation
               : RevocationStrategy::NoRevocation;
  if (F.containsPossiblyEscapingLocals())
    return RevocationStrategy::ConditionalRevocation;
  else
    return RevocationStrategy::NoRevocation;
}

Value *CheriCapDerivedLifetimes::getFramePointer(LLVMContext &Context,
                                                 IRBuilder<> &Builder) const {
  unsigned AS = Type::getVoidTy(Context)->getPointerAddressSpace();
  Type *VoidPtrTy = Type::getVoidTy(Context)->getPointerTo(AS);
  Type *Int32Ty = IntegerType::getInt32Ty(Context);
  Constant *Level = ConstantInt::get(Int32Ty, 0);
  return Builder.CreateIntrinsic(Intrinsic::frameaddress, {VoidPtrTy}, {Level});
}

char CheriCapDerivedLifetimes::ID;
INITIALIZE_PASS(CheriCapDerivedLifetimes, DEBUG_TYPE, PASS_NAME, false, false)

ModulePass *llvm::createCheriCapDerivedLifetimesPass() {
  return new CheriCapDerivedLifetimes();
}
