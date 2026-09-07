# Module tests

Folder-based end-to-end tests for the sic module system (sic.md §"Imports"),
driven by `../moduletest_rust.sh` (mirrors `compiletest_rust.sh`).

Each subdirectory is one test case. Layout:

- `mod-<name>/` — one directory per module to build with `sic --emit-module`.
  Built in sorted order, each adding a `-I` for the ones after it, so a module
  can import another local module built earlier (name it to sort first).
- `main.sic` — the consumer, compiled against those `-I`s plus the std sysroot.
- `main.res` — expected process exit code (default `0`).
- `main.out` — expected exact stdout (optional).
- `no-valgrind` — marker: skip the valgrind leak/error check for this case.

A case with no `mod-*/` directory is a pure-`std` test (std resolves via the
sysroot installed by `build.sh`). Every case is run under valgrind and must be
leak-/error-clean unless it opts out.
