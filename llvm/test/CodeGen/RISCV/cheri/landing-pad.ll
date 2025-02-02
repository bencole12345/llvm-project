; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; Previously crashed at -O0 with "Impossible reg-to-reg copy" (optimisations
; folded the COPY such that it didn't trip up the verifier).
; RUN: %riscv32_cheri_purecap_llc -verify-machineinstrs -O0 < %s \
; RUN:   | FileCheck -check-prefix=RV32IXCHERI %s
; RUN: %riscv64_cheri_purecap_llc -verify-machineinstrs -O0 < %s \
; RUN:   | FileCheck -check-prefix=RV64IXCHERI %s

declare void @throw_exception() addrspace(200)

declare i32 @__gxx_personality_v0(...) addrspace(200)

declare i8 addrspace(200)* @__cxa_begin_catch(i8 addrspace(200)*) addrspace(200)

declare void @__cxa_end_catch() addrspace(200)

define void @test() addrspace(200) personality i8 addrspace(200)* bitcast (i32 (...) addrspace(200)* @__gxx_personality_v0 to i8 addrspace(200)*) {
; RV32IXCHERI-LABEL: test:
; RV32IXCHERI:       # %bb.0: # %entry
; RV32IXCHERI-NEXT:    cincoffset csp, csp, -32
; RV32IXCHERI-NEXT:    .cfi_def_cfa_offset 32
; RV32IXCHERI-NEXT:    csc cra, 24(csp)
; RV32IXCHERI-NEXT:    .cfi_offset ra, -8
; RV32IXCHERI-NEXT:  .Ltmp0:
; RV32IXCHERI-NEXT:  .LBB0_3: # %entry
; RV32IXCHERI-NEXT:    # Label of block must be emitted
; RV32IXCHERI-NEXT:    auipcc ca0, %captab_pcrel_hi(throw_exception)
; RV32IXCHERI-NEXT:    clc ca0, %pcrel_lo(.LBB0_3)(ca0)
; RV32IXCHERI-NEXT:    cjalr ca0
; RV32IXCHERI-NEXT:  .Ltmp1:
; RV32IXCHERI-NEXT:    j .LBB0_2
; RV32IXCHERI-NEXT:  .LBB0_1: # %lpad
; RV32IXCHERI-NEXT:  .Ltmp2:
; RV32IXCHERI-NEXT:  .LBB0_4: # %lpad
; RV32IXCHERI-NEXT:    # Label of block must be emitted
; RV32IXCHERI-NEXT:    auipcc ca2, %captab_pcrel_hi(__cxa_begin_catch)
; RV32IXCHERI-NEXT:    clc ca2, %pcrel_lo(.LBB0_4)(ca2)
; RV32IXCHERI-NEXT:    csw a1, 20(csp)
; RV32IXCHERI-NEXT:    cjalr ca2
; RV32IXCHERI-NEXT:  .LBB0_5: # %lpad
; RV32IXCHERI-NEXT:    # Label of block must be emitted
; RV32IXCHERI-NEXT:    auipcc ca1, %captab_pcrel_hi(__cxa_end_catch)
; RV32IXCHERI-NEXT:    clc ca1, %pcrel_lo(.LBB0_5)(ca1)
; RV32IXCHERI-NEXT:    csc ca0, 8(csp)
; RV32IXCHERI-NEXT:    cjalr ca1
; RV32IXCHERI-NEXT:    j .LBB0_2
; RV32IXCHERI-NEXT:  .LBB0_2: # %try.cont
; RV32IXCHERI-NEXT:    clc cra, 24(csp)
; RV32IXCHERI-NEXT:    cincoffset csp, csp, 32
; RV32IXCHERI-NEXT:    cret
;
; RV64IXCHERI-LABEL: test:
; RV64IXCHERI:       # %bb.0: # %entry
; RV64IXCHERI-NEXT:    cincoffset csp, csp, -48
; RV64IXCHERI-NEXT:    .cfi_def_cfa_offset 48
; RV64IXCHERI-NEXT:    csc cra, 32(csp)
; RV64IXCHERI-NEXT:    .cfi_offset ra, -16
; RV64IXCHERI-NEXT:  .Ltmp0:
; RV64IXCHERI-NEXT:  .LBB0_3: # %entry
; RV64IXCHERI-NEXT:    # Label of block must be emitted
; RV64IXCHERI-NEXT:    auipcc ca0, %captab_pcrel_hi(throw_exception)
; RV64IXCHERI-NEXT:    clc ca0, %pcrel_lo(.LBB0_3)(ca0)
; RV64IXCHERI-NEXT:    cjalr ca0
; RV64IXCHERI-NEXT:  .Ltmp1:
; RV64IXCHERI-NEXT:    j .LBB0_2
; RV64IXCHERI-NEXT:  .LBB0_1: # %lpad
; RV64IXCHERI-NEXT:  .Ltmp2:
; RV64IXCHERI-NEXT:  .LBB0_4: # %lpad
; RV64IXCHERI-NEXT:    # Label of block must be emitted
; RV64IXCHERI-NEXT:    auipcc ca2, %captab_pcrel_hi(__cxa_begin_catch)
; RV64IXCHERI-NEXT:    clc ca2, %pcrel_lo(.LBB0_4)(ca2)
; RV64IXCHERI-NEXT:    csd a1, 24(csp)
; RV64IXCHERI-NEXT:    cjalr ca2
; RV64IXCHERI-NEXT:  .LBB0_5: # %lpad
; RV64IXCHERI-NEXT:    # Label of block must be emitted
; RV64IXCHERI-NEXT:    auipcc ca1, %captab_pcrel_hi(__cxa_end_catch)
; RV64IXCHERI-NEXT:    clc ca1, %pcrel_lo(.LBB0_5)(ca1)
; RV64IXCHERI-NEXT:    csc ca0, 0(csp)
; RV64IXCHERI-NEXT:    cjalr ca1
; RV64IXCHERI-NEXT:    j .LBB0_2
; RV64IXCHERI-NEXT:  .LBB0_2: # %try.cont
; RV64IXCHERI-NEXT:    clc cra, 32(csp)
; RV64IXCHERI-NEXT:    cincoffset csp, csp, 48
; RV64IXCHERI-NEXT:    cret
entry:
  invoke void @throw_exception() to label %try.cont unwind label %lpad

lpad:
  %0 = landingpad { i8 addrspace(200)*, i32 } catch i8 addrspace(200)* null
  %1 = extractvalue { i8 addrspace(200)*, i32 } %0, 0
  %2 = tail call i8 addrspace(200)* @__cxa_begin_catch(i8 addrspace(200)* %1)
  tail call void @__cxa_end_catch()
  br label %try.cont

try.cont:
  ret void
}
