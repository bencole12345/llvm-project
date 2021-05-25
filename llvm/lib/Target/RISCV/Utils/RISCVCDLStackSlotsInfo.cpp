#include "RISCVCDLStackSlotsInfo.h"

namespace llvm {

unsigned RISCVCDLStackSlotsInfo::getSize(CDLStackSlot slot) const {
  switch (slot) {
  case CDLStackSlot::ViolationHappened:
    return _escaping ? 4 : 0;
  case CDLStackSlot::SavedSP:
    return 16;
  case CDLStackSlot::SavedFP:
    return _hasFP ? 16 : 0;
  }
}

unsigned RISCVCDLStackSlotsInfo::getOffset(CDLStackSlot slot) const {
  switch (slot) {
  case CDLStackSlot::ViolationHappened:
    assert(!_escaping);
    return getSize(CDLStackSlot::ViolationHappened);
  case CDLStackSlot::SavedSP:
    return getSize(CDLStackSlot::ViolationHappened) +
           getSize(CDLStackSlot::SavedSP);
  case CDLStackSlot::SavedFP:
    assert(_hasFP);
    return getSize(CDLStackSlot::ViolationHappened) +
           getSize(CDLStackSlot::SavedSP) + getSize(CDLStackSlot::SavedFP);
  }
}

unsigned RISCVCDLStackSlotsInfo::totalSize() const {
return getSize(CDLStackSlot::ViolationHappened) +
getSize(CDLStackSlot::SavedSP) + getSize(CDLStackSlot::SavedFP);
}



} // namespace llvm
