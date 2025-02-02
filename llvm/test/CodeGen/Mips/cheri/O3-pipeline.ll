; RUN: llc -mtriple=mips64-unknown-freebsd -O3 -debug-pass=Structure < %s -o /dev/null 2>&1 | grep -v "Verify generated machine code" | FileCheck %s -check-prefixes CHECK,MIPS
; RUN: %cheri_llc -O3 -debug-pass=Structure < %s -o /dev/null 2>&1 | grep -v "Verify generated machine code" | FileCheck %s -check-prefixes CHECK,CHERI
; RUN: %cheri_purecap_llc -O3 -debug-pass=Structure < %s -o /dev/null 2>&1 | grep -v "Verify generated machine code" | FileCheck %s -check-prefixes CHECK,CHERI

; REQUIRES: asserts

; CHECK-LABEL: Pass Arguments:
; CHECK-NEXT:Target Library Information
; CHECK-NEXT:Target Pass Configuration
; CHECK-NEXT:Machine Module Information
; CHECK-NEXT:Target Transform Information
; CHECK-NEXT:Type-Based Alias Analysis
; CHECK-NEXT:Scoped NoAlias Alias Analysis
; CHECK-NEXT:Assumption Cache Tracker
; CHECK-NEXT:Profile summary info
; CHECK-NEXT:Create Garbage Collector Module Metadata
; CHECK-NEXT:Machine Branch Probability Analysis
; CHECK-NEXT:  ModulePass Manager
; CHECK-NEXT:    Pre-ISel Intrinsic Lowering
; CHECK-NEXT:    FunctionPass Manager
; CHECK-NEXT:      Module Verifier
; CHECK-NEXT:      Dominator Tree Construction
; CHECK-NEXT:      Basic Alias Analysis (stateless AA impl)
; CHECK-NEXT:      Natural Loop Information
; CHECK-NEXT:      Canonicalize natural loops
; CHECK-NEXT:      Scalar Evolution Analysis
; CHECK-NEXT:      Loop Pass Manager
; CHECK-NEXT:        Canonicalize Freeze Instructions in Loops
; CHECK-NEXT:        Induction Variable Users
; CHECK-NEXT:        Loop Strength Reduction
; CHECK-NEXT:      Basic Alias Analysis (stateless AA impl)
; CHECK-NEXT:      Function Alias Analysis Results
; CHECK-NEXT:      Merge contiguous icmps into a memcmp
; CHECK-NEXT:      Natural Loop Information
; CHECK-NEXT:      Lazy Branch Probability Analysis
; CHECK-NEXT:      Lazy Block Frequency Analysis
; CHECK-NEXT:      Expand memcmp() to load/stores
; CHECK-NEXT:      Lower Garbage Collection Instructions
; CHECK-NEXT:      Shadow Stack GC Lowering
; CHECK-NEXT:      Lower constant intrinsics
; CHECK-NEXT:      Remove unreachable blocks from the CFG
; CHECK-NEXT:      Dominator Tree Construction
; CHECK-NEXT:      Natural Loop Information
; CHECK-NEXT:      Post-Dominator Tree Construction
; CHECK-NEXT:      Branch Probability Analysis
; CHECK-NEXT:      Block Frequency Analysis
; CHECK-NEXT:      Constant Hoisting
; CHECK-NEXT:      Partially inline calls to library functions
; CHECK-NEXT:      Instrument function entry/exit with calls to e.g. mcount() (post inlining)
; CHECK-NEXT:      Scalarize Masked Memory Intrinsics
; CHECK-NEXT:      Expand reduction intrinsics
; CHECK-NEXT:      Expand Atomic instructions
; CHECK-NEXT:      Dominator Tree Construction
; CHECK-NEXT:      Natural Loop Information
; CHERI-NEXT:      Scalar Evolution Analysis
; CHERI-NEXT:      CheriLoopPointerDecanonicalize
; CHERI-NEXT:      Post-Dominator Tree Construction
; CHERI-NEXT:      Aggressive Dead Code Elimination
; CHERI-NEXT:      CHERI range checker
; CHERI-NEXT:    CHERI bound stack allocations
; CHERI-NEXT:    FunctionPass Manager
; CHERI-NEXT:      Dominator Tree Construction
; CHERI-NEXT:      Natural Loop Information
; CHECK-NEXT:      CodeGen Prepare
; CHECK-NEXT:    Rewrite Symbols
; CHECK-NEXT:    FunctionPass Manager
; CHECK-NEXT:      Dominator Tree Construction
; CHECK-NEXT:      Exception handling preparation
; CHECK-NEXT:      Safe Stack instrumentation pass
; CHECK-NEXT:      Insert stack protectors
; CHECK-NEXT:      Module Verifier
; CHECK-NEXT:      MIPS DAG->DAG Pattern Instruction Selection
; CHECK-NEXT:      Dominator Tree Construction
; CHECK-NEXT:      Basic Alias Analysis (stateless AA impl)
; CHECK-NEXT:      Function Alias Analysis Results
; CHECK-NEXT:      Natural Loop Information
; CHECK-NEXT:      Post-Dominator Tree Construction
; CHECK-NEXT:      Branch Probability Analysis
; CHECK-NEXT:      Lazy Branch Probability Analysis
; CHECK-NEXT:      Lazy Block Frequency Analysis
; CHECK-NEXT:      MIPS DAG->DAG Pattern Instruction Selection
; CHECK-NEXT:      Post-Dominator Tree Construction
; CHECK-NEXT:      Branch Probability Analysis
; CHECK-NEXT:      Lazy Branch Probability Analysis
; CHECK-NEXT:      Lazy Block Frequency Analysis
; CHECK-NEXT:      MIPS DAG->DAG Pattern Instruction Selection
; CHECK-NEXT:      Finalize ISel and expand pseudo-instructions
; CHECK-NEXT:      Lazy Machine Block Frequency Analysis
; CHECK-NEXT:      Early Tail Duplication
; CHECK-NEXT:      Optimize machine instruction PHIs
; CHECK-NEXT:      Slot index numbering
; CHECK-NEXT:      Merge disjoint stack slots
; CHECK-NEXT:      Local Stack Slot Allocation
; CHECK-NEXT:      Remove dead machine instructions
; CHECK-NEXT:      MachineDominator Tree Construction
; CHECK-NEXT:      Machine Natural Loop Construction
; CHECK-NEXT:      Early Machine Loop Invariant Code Motion
; CHECK-NEXT:      MachineDominator Tree Construction
; CHECK-NEXT:      Machine Block Frequency Analysis
; CHECK-NEXT:      Machine Common Subexpression Elimination
; CHECK-NEXT:      MachinePostDominator Tree Construction
; CHECK-NEXT:      Machine code sinking
; CHECK-NEXT:      Peephole Optimizations
; CHECK-NEXT:      Remove dead machine instructions
; CHECK-NEXT:      MachineDominator Tree Construction
; CHECK-NEXT:      Mips MipsOptimizePICCall
; CHERI-NEXT:      MachineDominator Tree Construction
; CHERI-NEXT:      Machine Natural Loop Construction
; CHERI-NEXT:      MachinePostDominator Tree Construction
; CHERI-NEXT:      Cheri Addressing Mode Folder
; CHERI-NEXT:      Remove dead machine instructions
; CHERI-NEXT:      Cheri128 fail hard
; CHECK-NEXT:      Detect Dead Lanes
; CHECK-NEXT:      Process Implicit Definitions
; CHECK-NEXT:      Remove unreachable machine basic blocks
; CHECK-NEXT:      Live Variable Analysis
; CHECK-NEXT:      MachineDominator Tree Construction
; CHECK-NEXT:      Machine Natural Loop Construction
; CHECK-NEXT:      Eliminate PHI nodes for register allocation
; CHECK-NEXT:      Two-Address instruction pass
; CHECK-NEXT:      Slot index numbering
; CHECK-NEXT:      Live Interval Analysis
; CHECK-NEXT:      Simple Register Coalescing
; CHECK-NEXT:      Rename Disconnected Subregister Components
; CHECK-NEXT:      Machine Instruction Scheduler
; CHECK-NEXT:      Machine Block Frequency Analysis
; CHECK-NEXT:      Debug Variable Analysis
; CHECK-NEXT:      Live Stack Slot Analysis
; CHECK-NEXT:      Virtual Register Map
; CHECK-NEXT:      Live Register Matrix
; CHECK-NEXT:      Bundle Machine CFG Edges
; CHECK-NEXT:      Spill Code Placement Analysis
; CHECK-NEXT:      Lazy Machine Block Frequency Analysis
; CHECK-NEXT:      Machine Optimization Remark Emitter
; CHECK-NEXT:      Greedy Register Allocator
; CHECK-NEXT:      Virtual Register Rewriter
; CHECK-NEXT:      Stack Slot Coloring
; CHECK-NEXT:      Machine Copy Propagation Pass
; CHECK-NEXT:      Machine Loop Invariant Code Motion
; CHERI-NEXT:      CHERI invalidate pass
; CHECK-NEXT:      Fixup Statepoint Caller Saved
; CHECK-NEXT:      PostRA Machine Sink
; CHERI-NEXT:      MachineDominator Tree Construction
; CHERI-NEXT:      Machine Natural Loop Construction
; CHECK-NEXT:      Machine Block Frequency Analysis
; MIPS-NEXT:       MachineDominator Tree Construction
; CHECK-NEXT:      MachinePostDominator Tree Construction
; CHECK-NEXT:      Lazy Machine Block Frequency Analysis
; CHECK-NEXT:      Machine Optimization Remark Emitter
; CHECK-NEXT:      Shrink Wrapping analysis
; CHECK-NEXT:      Prologue/Epilogue Insertion & Frame Finalization
; CHECK-NEXT:      Control Flow Optimizer
; CHECK-NEXT:      Lazy Machine Block Frequency Analysis
; CHECK-NEXT:      Tail Duplication
; CHECK-NEXT:      Machine Copy Propagation Pass
; CHECK-NEXT:      Post-RA pseudo instruction expansion pass
; CHECK-NEXT:      MachineDominator Tree Construction
; CHECK-NEXT:      Machine Natural Loop Construction
; CHECK-NEXT:      Post RA top-down list latency scheduler
; CHECK-NEXT:      Analyze Machine Code For Garbage Collection
; CHECK-NEXT:      Machine Block Frequency Analysis
; CHECK-NEXT:      MachinePostDominator Tree Construction
; CHECK-NEXT:      Branch Probability Basic Block Placement
; CHECK-NEXT:      Insert fentry calls
; CHECK-NEXT:      Insert XRay ops
; CHECK-NEXT:      Implement the 'patchable-function' attribute
; CHECK-NEXT:      Mips pseudo instruction expansion pass
; CHECK-NEXT:      microMIPS instruction size reduction pass
; CHECK-NEXT:      Mips Delay Slot Filler
; CHECK-NEXT:      Mips Branch Expansion Pass
; CHECK-NEXT:      Mips Constant Islands
; CHECK-NEXT:      Contiguously Lay Out Funclets
; CHECK-NEXT:      StackMap Liveness Analysis
; CHECK-NEXT:      Live DEBUG_VALUE analysis
; CHECK-NEXT:      Lazy Machine Block Frequency Analysis
; CHECK-NEXT:      Machine Optimization Remark Emitter
; CHECK-NEXT:      Mips Assembly Printer
; CHECK-NEXT:      Free MachineFunction

define void @f() {
  ret void
}
