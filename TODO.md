- [x] -pthread
- [x] alignof
- [x] sqlite
- [x] tests for recent changes and fixes
- [ ] optimizations
- [x] sic frontend
- [ ] AVX2 and SSE2 and 256 bit vector
- [x] doc under doc/
- [x] char b[10]; b[0] = 'H'; b[1] = 'i'; b[2] = 0; string s = b; return s;
- [x] allow `del` on strings. It decreases refcount and invalidates the one instance. `string a = "hello"; string b = c; del a; .. ` would invalidate `a` and dec ref, but b would be valid until end of scope.
- [x] easy enum to str like `enum vals { NONE, ONE, TWO }; enum vals = ONE; vals.str // This should be "vals::ONE" as native string` 

## Gaps found while writing doc/ (spec vs. implementation)

- [x] **Tagged enum with a `fixed` payload crashes.** FIXED (84aecda). Root cause:
      enum construction lowered a `fixed`/`bigint` payload arg with a bare
      `lower_expr`+`store_lvalue`, so a literal stored raw float bits (not a
      `__sic_rat*`) and any source stored a shared pointer freed independently →
      use-after-free. Now uses `eval_fixed_owned`/`eval_bigint_owned` (own copy,
      like the string-payload retain). fixed + bigint payloads roundtrip; test_0269.
- [ ] **`(int)bigint` cast gives garbage** (pre-existing, not payload-specific).
      `bigint b = 42; (int)b` → garbage even for a plain local. Likely the bigint→
      int narrowing cast reads the pointer instead of the low limb. `bigint.str`
      and bigint arithmetic are correct; only the `(int)` cast is wrong.
- [ ] **bigint integer literal > i64 truncates** (pre-existing). `bigint b =
      12345678901234567890;` stores the value reinterpreted as signed i64 (differs
      by 2^64). A large literal is parsed as i64 before promotion to bigint; the
      literal path needs to keep >64-bit magnitudes (decimal-string → `__sic_bi_from`).
- [ ] **Enum payloads are never freed at scope exit** (leak, not a crash). An owned
      `fixed`/`bigint`/`string` stored in a tagged enum leaks when the enum value
      dies — no enum-payload RAII. The crash fix trades a use-after-free for this
      leak (consistent with the existing string-payload behaviour).
- [x] **char / Unicode.** DECIDED: keep `char` as a plain C `char` (8-bit signed)
      and all C interop unchanged — do NOT make it unsigned/UTF-8, and drop the
      spec's `byte`/`unsigned byte`. Instead added `u8char` (a 32-bit Unicode code
      point) + `string.utf8` for Unicode work (commit 8318aff). The spec's
      unsigned/4-byte `char` and `byte` types are intentionally not pursued.
- [ ] **Namespaced module VARIABLE access `mod.var` fails.** `import math;
      math.sq(5)` (a call) works, but `math.meaning` (an exported `var`, present
      in the `.smod` manifest as `var meaning i32 math_meaning`) gives "undefined
      name 'math'". Only function calls resolve through a module namespace; var
      exports don't. Selective import (`import math.sq as square;`) works.
