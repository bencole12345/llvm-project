//===-- RISCVRegisterInfo.cpp - RISCV Register Information ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the RISCV implementation of the TargetRegisterInfo class.
//
//===----------------------------------------------------------------------===//

#include "RISCVRegisterInfo.h"
#include "RISCV.h"
#include "RISCVMachineFunctionInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineFrameInfo.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/RegisterScavenging.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/Support/ErrorHandling.h"

#define GET_REGINFO_TARGET_DESC
#include "RISCVGenRegisterInfo.inc"

using namespace llvm;

static_assert(RISCV::X1 == RISCV::X0 + 1, "Register list not consecutive");
static_assert(RISCV::X31 == RISCV::X0 + 31, "Register list not consecutive");
static_assert(RISCV::F1_F == RISCV::F0_F + 1, "Register list not consecutive");
static_assert(RISCV::F31_F == RISCV::F0_F + 31,
              "Register list not consecutive");
static_assert(RISCV::F1_D == RISCV::F0_D + 1, "Register list not consecutive");
static_assert(RISCV::F31_D == RISCV::F0_D + 31,
              "Register list not consecutive");
static_assert(RISCV::V1 == RISCV::V0 + 1, "Register list not consecutive");
static_assert(RISCV::V31 == RISCV::V0 + 31, "Register list not consecutive");

RISCVRegisterInfo::RISCVRegisterInfo(const RISCVSubtarget &STI)
    : RISCVGenRegisterInfo(RISCVABI::isCheriPureCapABI(STI.getTargetABI())
                               ? RISCV::C1 : RISCV::X1,
                           /*DwarfFlavour*/0, /*EHFlavor*/0,
                           /*PC*/0, STI.getHwMode()) {}

const MCPhysReg *
RISCVRegisterInfo::getCalleeSavedRegs(const MachineFunction *MF) const {
  auto &Subtarget = MF->getSubtarget<RISCVSubtarget>();
  if (MF->getFunction().hasFnAttribute("interrupt")) {
    if (Subtarget.hasStdExtD())
      return Subtarget.hasCheri() ? CSR_XLEN_CLEN_F64_Interrupt_SaveList
                                  : CSR_XLEN_F64_Interrupt_SaveList;
    if (Subtarget.hasStdExtF())
      return Subtarget.hasCheri() ? CSR_XLEN_CLEN_F32_Interrupt_SaveList
                                  : CSR_XLEN_F32_Interrupt_SaveList;
    return Subtarget.hasCheri() ? CSR_XLEN_CLEN_Interrupt_SaveList
                                : CSR_Interrupt_SaveList;
  }

  switch (Subtarget.getTargetABI()) {
  default:
    llvm_unreachable("Unrecognized ABI");
  case RISCVABI::ABI_ILP32:
  case RISCVABI::ABI_LP64:
    return CSR_ILP32_LP64_SaveList;
  case RISCVABI::ABI_IL32PC64:
  case RISCVABI::ABI_L64PC128:
    return CSR_IL32PC64_L64PC128_SaveList;
  case RISCVABI::ABI_ILP32F:
  case RISCVABI::ABI_LP64F:
    return CSR_ILP32F_LP64F_SaveList;
  case RISCVABI::ABI_IL32PC64F:
  case RISCVABI::ABI_L64PC128F:
    return CSR_IL32PC64F_L64PC128F_SaveList;
  case RISCVABI::ABI_ILP32D:
  case RISCVABI::ABI_LP64D:
    return CSR_ILP32D_LP64D_SaveList;
  case RISCVABI::ABI_IL32PC64D:
  case RISCVABI::ABI_L64PC128D:
    return CSR_IL32PC64D_L64PC128D_SaveList;
  }
}

BitVector RISCVRegisterInfo::getReservedRegs(const MachineFunction &MF) const {
  const RISCVFrameLowering *TFI = getFrameLowering(MF);
  const RISCVSubtarget &STI = MF.getSubtarget<RISCVSubtarget>();
  BitVector Reserved(getNumRegs());

  // Mark any registers requested to be reserved as such
  for (size_t Reg = 0; Reg < getNumRegs(); Reg++) {
    if (STI.isRegisterReservedByUser(Reg))
      markSuperRegs(Reserved, Reg);
  }

  // Use markSuperRegs to ensure any register aliases are also reserved
  markSuperRegs(Reserved, RISCV::X0); // zero
  markSuperRegs(Reserved, RISCV::X2); // sp
  markSuperRegs(Reserved, RISCV::X3); // gp
  markSuperRegs(Reserved, RISCV::X4); // tp
  if (TFI->hasFP(MF))
    markSuperRegs(Reserved, RISCV::X8); // fp

  markSuperRegs(Reserved, RISCV::C0); // cnull
  markSuperRegs(Reserved, RISCV::C2); // csp
  markSuperRegs(Reserved, RISCV::C3); // cgp
  markSuperRegs(Reserved, RISCV::C4); // ctp
  if (TFI->hasFP(MF))
    markSuperRegs(Reserved, RISCV::C8); // cfp

  markSuperRegs(Reserved, RISCV::DDC);

  // Reserve the base register if we need to realign the stack and allocate
  // variable-sized objects at runtime.
  if (TFI->hasBP(MF))
    markSuperRegs(Reserved, RISCVABI::getBPReg(STI.getTargetABI())); // (c)bp
  assert(checkAllSuperRegsMarked(Reserved));
  return Reserved;
}

bool RISCVRegisterInfo::isAsmClobberable(const MachineFunction &MF,
                                         MCRegister PhysReg) const {
  return !MF.getSubtarget<RISCVSubtarget>().isRegisterReservedByUser(PhysReg);
}

bool RISCVRegisterInfo::isConstantPhysReg(MCRegister PhysReg) const {
  return PhysReg == RISCV::X0 || PhysReg == RISCV::C0;
}

const uint32_t *RISCVRegisterInfo::getNoPreservedMask() const {
  return CSR_NoRegs_RegMask;
}

// Frame indexes representing locations of CSRs which are given a fixed location
// by save/restore libcalls.
static const std::map<unsigned, int> FixedCSRFIMap = {
  {/*ra*/  RISCV::X1,   -1},
  {/*s0*/  RISCV::X8,   -2},
  {/*s1*/  RISCV::X9,   -3},
  {/*s2*/  RISCV::X18,  -4},
  {/*s3*/  RISCV::X19,  -5},
  {/*s4*/  RISCV::X20,  -6},
  {/*s5*/  RISCV::X21,  -7},
  {/*s6*/  RISCV::X22,  -8},
  {/*s7*/  RISCV::X23,  -9},
  {/*s8*/  RISCV::X24,  -10},
  {/*s9*/  RISCV::X25,  -11},
  {/*s10*/ RISCV::X26,  -12},
  {/*s11*/ RISCV::X27,  -13}
};

bool RISCVRegisterInfo::hasReservedSpillSlot(const MachineFunction &MF,
                                             Register Reg,
                                             int &FrameIdx) const {
  const auto *RVFI = MF.getInfo<RISCVMachineFunctionInfo>();
  if (!RVFI->useSaveRestoreLibCalls(MF))
    return false;

  auto FII = FixedCSRFIMap.find(Reg);
  if (FII == FixedCSRFIMap.end())
    return false;

  FrameIdx = FII->second;
  return true;
}

void RISCVRegisterInfo::eliminateFrameIndex(MachineBasicBlock::iterator II,
                                            int SPAdj, unsigned FIOperandNum,
                                            RegScavenger *RS) const {
  assert(SPAdj == 0 && "Unexpected non-zero SPAdj value");

  MachineInstr &MI = *II;
  MachineFunction &MF = *MI.getParent()->getParent();
  MachineRegisterInfo &MRI = MF.getRegInfo();
  const RISCVSubtarget &STI = MF.getSubtarget<RISCVSubtarget>();
  const RISCVInstrInfo *TII = STI.getInstrInfo();
  DebugLoc DL = MI.getDebugLoc();

  int FrameIndex = MI.getOperand(FIOperandNum).getIndex();
  Register FrameReg;
  int Offset =
      getFrameLowering(MF)->getFrameIndexReference(MF, FrameIndex, FrameReg) +
      MI.getOperand(FIOperandNum + 1).getImm();

  if (!isInt<32>(Offset)) {
    report_fatal_error(
        "Frame offsets outside of the signed 32-bit range not supported");
  }

  MachineBasicBlock &MBB = *MI.getParent();
  bool FrameRegIsKill = false;

  if (!isInt<12>(Offset)) {
    assert(isInt<32>(Offset) && "Int32 expected");
    // The offset won't fit in an immediate, so use a scratch register instead
    // Modify Offset and FrameReg appropriately
    unsigned Opc;
    Register ScratchReg = MRI.createVirtualRegister(&RISCV::GPRRegClass);
    Register DestReg;
    if (RISCVABI::isCheriPureCapABI(STI.getTargetABI())) {
      Opc = RISCV::CIncOffset;
      DestReg = MRI.createVirtualRegister(&RISCV::GPCRRegClass);
    } else {
      Opc = RISCV::ADD;
      DestReg = ScratchReg;
    }

    TII->movImm(MBB, II, DL, ScratchReg, Offset);
    BuildMI(MBB, II, DL, TII->get(Opc), DestReg)
        .addReg(FrameReg)
        .addReg(ScratchReg, RegState::Kill);
    Offset = 0;
    FrameReg = DestReg;
    FrameRegIsKill = true;
  }

  MI.getOperand(FIOperandNum)
      .ChangeToRegister(FrameReg, false, false, FrameRegIsKill);
  MI.getOperand(FIOperandNum + 1).ChangeToImmediate(Offset);
}

Register RISCVRegisterInfo::getFrameRegister(const MachineFunction &MF) const {
  const RISCVFrameLowering *TFI = getFrameLowering(MF);
  return TFI->hasFP(MF) ? TFI->getFPReg() : TFI->getSPReg();
}

const uint32_t *
RISCVRegisterInfo::getCallPreservedMask(const MachineFunction & MF,
                                        CallingConv::ID /*CC*/) const {
  auto &Subtarget = MF.getSubtarget<RISCVSubtarget>();

  switch (Subtarget.getTargetABI()) {
  default:
    llvm_unreachable("Unrecognized ABI");
  case RISCVABI::ABI_ILP32:
  case RISCVABI::ABI_LP64:
    return CSR_ILP32_LP64_RegMask;
  case RISCVABI::ABI_IL32PC64:
  case RISCVABI::ABI_L64PC128:
    return CSR_IL32PC64_L64PC128_RegMask;
  case RISCVABI::ABI_ILP32F:
  case RISCVABI::ABI_LP64F:
    return CSR_ILP32F_LP64F_RegMask;
  case RISCVABI::ABI_IL32PC64F:
  case RISCVABI::ABI_L64PC128F:
    return CSR_IL32PC64F_L64PC128F_RegMask;
  case RISCVABI::ABI_ILP32D:
  case RISCVABI::ABI_LP64D:
    return CSR_ILP32D_LP64D_RegMask;
  case RISCVABI::ABI_IL32PC64D:
  case RISCVABI::ABI_L64PC128D:
    return CSR_IL32PC64D_L64PC128D_RegMask;
  }
}
