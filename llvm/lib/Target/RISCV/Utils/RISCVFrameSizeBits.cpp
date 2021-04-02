//===- RISCVFrameSizeBits.cpp - Size bits for stack frames ----*- C++ -*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "RISCVFrameSizeBits.h"

#include "llvm/Support/ErrorHandling.h"

namespace llvm {
namespace RISCVFrameSizeBits {

// TODO: Add tests for output

unsigned getFrameSizeBits(uint64_t StackFrameSize) {
  constexpr unsigned MinRepresentibleSize = 64;
  constexpr unsigned MaxRepresentibleSize = MinRepresentibleSize << 6;
  if (StackFrameSize > MaxRepresentibleSize) {
    // TODO: It's heap time
    llvm_unreachable("Stack frame too big, can't provide temporal safety");
    return 0;
  }
  unsigned Bits = 1;
  StackFrameSize /= MinRepresentibleSize;
  while (StackFrameSize) {
    Bits++;
    StackFrameSize >>= 1;
  }
  return Bits;
}

unsigned getNumBitsAlignmentRequired(uint64_t StackFrameSize) {
  unsigned N = 0;
  while (StackFrameSize > 1) {
    N++;
    StackFrameSize >>= 1;
  }
  return N;
}

} // namespace RISCVFrameSizeBits
} // namespace llvm
