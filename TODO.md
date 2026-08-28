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
- [ ] easy enum to str like `enum vals { NONE, ONE, TWO }; enum vals = ONE; vals.str // This should be "vals::ONE" as native string` 

## Gaps found while writing doc/ (spec vs. implementation)

- [ ] **Tagged enum with a `fixed` payload crashes.** `enum Shape { Circle(fixed),
      Square(fixed) }; ... match (s) { Circle(r): return r*r*3.14159; ... }`
      segfaults (exit 139). Int payloads and generic `Option<int>` work; `fixed`
      (and likely bigint/string?) payloads in a non-generic enum need
      investigation.
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
