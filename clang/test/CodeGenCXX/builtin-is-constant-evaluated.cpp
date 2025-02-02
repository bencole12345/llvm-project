// RUN: %clang_cc1 -triple x86_64-unknown-unknown -emit-llvm %s -std=c++2a -o %t.ll
// RUN: FileCheck -check-prefix=CHECK-FN-CG -input-file=%t.ll %s
// RUN: FileCheck -check-prefix=CHECK-STATIC -input-file=%t.ll %s
// RUN: FileCheck -check-prefix=CHECK-DYN -input-file=%t.ll %s
// RUN: FileCheck -check-prefix=CHECK-ARR -input-file=%t.ll %s
// RUN: FileCheck -check-prefix=CHECK-FOLD -input-file=%t.ll %s

using size_t = decltype(sizeof(int));

#define CONSTINIT __attribute__((require_constant_initialization))

extern "C" [[noreturn]] void BOOM();
extern "C" void OK();
extern "C" size_t RANDU();

namespace std {
inline constexpr bool is_constant_evaluated() noexcept {
  return __builtin_is_constant_evaluated();
}
} // namespace std

// CHECK-FN-CG-LABEL: define zeroext i1 @_Z3foov()
// CHECK-FN-CG: ret i1 false
bool foo() {
  return __builtin_is_constant_evaluated();
}

// CHECK-FN-CG-LABEL: define linkonce_odr i32 @_Z1fv()
constexpr int f() {
  // CHECK-FN-CG: store i32 13, i32* %n, align 4
  // CHECK-FN-CG: store i32 17, i32* %m, align 4
  // CHECK-FN-CG:  %1 = load i32, i32* %m, align 4
  // CHECK-FN-CG: %add = add nsw i32 %1, 13
  // CHECK-FN-CG: ret i32 %add
  const int n = __builtin_is_constant_evaluated() && std::is_constant_evaluated() ? 13 : 17; // n == 13
  int m = __builtin_is_constant_evaluated() ? 13 : 17;       // m might be 13 or 17 (see below)
  char arr[n] = {};                                          // char[13]
  return m + int(sizeof(arr));
}

// CHECK-STATIC-DAG: @p = global i32 26,
CONSTINIT int p = f(); // f().m == 13; initialized to 26
// CHECK-STATIC-DAG: @p2 = global i32 26,
int p2 = f(); // same result without CONSTINIT

// CHECK-DYN-LABEL: define internal void @__cxx_global_var_init()
// CHECK-DYN: %0 = load i32, i32* @p, align 4
// CHECK-DYN-NEXT: %call = call i32 @_Z1fv()
// CHECK-DYN-NEXT: %add = add nsw i32 %0, %call
// CHECK-DYN-NEXT: store i32 %add, i32* @q, align 4
// CHECK-DYN-NEXT: ret void
int q = p + f(); // m == 17 for this call; initialized to 56

int y;

// CHECK-STATIC-DAG: @b = global i32 2,
CONSTINIT int b = __builtin_is_constant_evaluated() ? 2 : y; // static initialization to 2

// CHECK-DYN-LABEL: define internal void @__cxx_global_var_init.1()
// CHECK-DYN: %0 = load i32, i32* @y, align 4
// CHECK-DYN: %1 = load i32, i32* @y, align 4
// CHECK-DYN-NEXT: %add = add
// CHECK-DYN-NEXT: store i32 %add, i32* @c,
int c = y + (__builtin_is_constant_evaluated() ? 2 : y); // dynamic initialization to y+y

// CHECK-DYN-LABEL: define internal void @__cxx_global_var_init.2()
// CHECK-DYN: store i32 1, i32* @_ZL1a, align 4
// CHECK-DYN-NEXT: ret void
const int a = __builtin_is_constant_evaluated() ? y : 1; // dynamic initialization to 1
const int *a_sink = &a;

// CHECK-ARR-LABEL: define void @_Z13test_arr_exprv
void test_arr_expr() {
  // CHECK-ARR: %x1 = alloca [101 x i8],
  char x1[std::is_constant_evaluated() && __builtin_is_constant_evaluated() ? 101 : 1];

  // CHECK-ARR: %x2 = alloca [42 x i8],
  char x2[std::is_constant_evaluated() && __builtin_is_constant_evaluated() ? 42 : RANDU()];

  // CHECK-ARR: call i8* @llvm.stacksave.p0i8()
  // CHECK-ARR: %vla = alloca i8, i64 13,
  char x3[std::is_constant_evaluated() || __builtin_is_constant_evaluated() ? RANDU() : 13];
}

// CHECK-ARR-LABEL: define void @_Z17test_new_arr_exprv
void test_new_arr_expr() {
  // CHECK-ARR: call noalias nonnull i8* @_Znam(i64 17)
  new char[std::is_constant_evaluated() || __builtin_is_constant_evaluated() ? 1 : 17];
}

// CHECK-FOLD-LABEL: @_Z31test_constant_initialized_locali(
bool test_constant_initialized_local(int k) {
  // CHECK-FOLD: store i8 1, i8* %n,
  // CHECK-FOLD: store volatile i8* %n, i8** %p,
  const bool n = __builtin_is_constant_evaluated() && std::is_constant_evaluated();
  const bool *volatile p = &n;
  return *p;
}

// CHECK-FOLD-LABEL: define void @_Z21test_ir_constant_foldv()
void test_ir_constant_fold() {
  // CHECK-FOLD-NEXT: entry:
  // CHECK-FOLD-NEXT: call void @OK()
  // CHECK-FOLD-NEXT: call void @OK()
  // CHECK-FOLD-NEXT: ret void
  if (std::is_constant_evaluated()) {
    BOOM();
  } else {
    OK();
  }
  std::is_constant_evaluated() ? BOOM() : OK();
}

// CHECK-STATIC-DAG: @ir = constant i32* @i_constant,
int i_constant;
int i_not_constant;
int &ir = __builtin_is_constant_evaluated() ? i_constant : i_not_constant;

// CHECK-FOLD-LABEL: @_Z35test_ref_initialization_local_scopev()
void test_ref_initialization_local_scope() {
  const int i_constant = 42;
  const int i_non_constant = 101;
  // CHECK-FOLD: store i32* %i_non_constant, i32** %r,
  const int &r = __builtin_is_constant_evaluated() ? i_constant : i_non_constant;
}

// CHECK-FOLD-LABEL: @_Z22test_ref_to_static_varv()
void test_ref_to_static_var() {
  static int i_constant = 42;
  static int i_non_constant = 101;
  // CHECK-FOLD: store i32* @_ZZ22test_ref_to_static_varvE10i_constant, i32** %r,
  int &r = __builtin_is_constant_evaluated() ? i_constant : i_non_constant;
}
