#ifndef LLVM_RISCVCAPDERIVEDLIFETIMESSTACKSLOTSINFO_H
#define LLVM_RISCVCAPDERIVEDLIFETIMESSTACKSLOTSINFO_H

#include <cassert>
#include <optional>

namespace llvm {

enum class CDLStackSlot { ViolationHappened, SavedSP, SavedFP };

class RISCVCDLStackSlotsInfo {
private:
  bool _escaping;
  bool _hasFP;

public:
  RISCVCDLStackSlotsInfo(bool escaping, bool hasFP)
      : _escaping(escaping), _hasFP(hasFP){};

  unsigned getSize(CDLStackSlot slot) const;

  unsigned getOffset(CDLStackSlot slot) const;

  unsigned totalSize() const;

  bool hasFP() const { return _hasFP; }
};

}

#endif // LLVM_RISCVCAPDERIVEDLIFETIMESSTACKSLOTSINFO_H
