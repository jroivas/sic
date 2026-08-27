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

## Gaps found while writing doc/ (spec vs. implementation)

- [ ] **Tagged enum with a `fixed` payload crashes.** `enum Shape { Circle(fixed),
      Square(fixed) }; ... match (s) { Circle(r): return r*r*3.14159; ... }`
      segfaults (exit 139). Int payloads and generic `Option<int>` work; `fixed`
      (and likely bigint/string?) payloads in a non-generic enum need
      investigation.
- [ ] **`char` is signed; spec says unsigned + UTF-8.** `char c = 200; c > 0` is
      false (c is -56). sic.md §"Integer sizes" specifies chars as unsigned and
      expandable to 4-byte UTF-8 code points — not implemented; `char` is a plain
      8-bit signed C char.
- [ ] **`byte` / `unsigned byte` types not implemented.** sic.md §"Integer sizes"
      lists signed `byte` (-128..127) and `unsigned byte` (0..255); the names are
      undefined in the compiler today (use `i8`/`u8`).
- [ ] **Namespaced module VARIABLE access `mod.var` fails.** `import math;
      math.sq(5)` (a call) works, but `math.meaning` (an exported `var`, present
      in the `.smod` manifest as `var meaning i32 math_meaning`) gives "undefined
      name 'math'". Only function calls resolve through a module namespace; var
      exports don't. Selective import (`import math.sq as square;`) works.
