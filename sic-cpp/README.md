# sic-cpp — Standalone C Preprocessor in SIC

A complete, standalone C preprocessor written entirely in [SIC](https://github.com/earendil-works/sic).
Replaces the external `cpp` in the sic compiler pipeline, removing the
dependency on a system C preprocessor.

## Status

This is a **first implementation** covering the core C preprocessor features
needed to bootstrap the sic compiler. It processes the system headers and user
code that the existing `cpp` handles.

### Implemented Directives

| Directive     | Status |
|---------------|--------|
| `#define`     | ✅ Object-like and function-like macros |
| `#undef`      | ✅ Remove macro definition |
| `#include`    | ✅ `"file"` and `<file>` search with `-I` paths |
| `#if`         | ✅ Integer constant expression evaluation |
| `#ifdef`      | ✅ Test macro definition |
| `#ifndef`     | ✅ Test macro not defined |
| `#elif`       | ✅ Chained conditional |
| `#else`       | ✅ Alternative branch |
| `#endif`      | ✅ Close conditional |
| `#error`      | ✅ Diagnostic and abort |
| `#warning`    | ✅ Diagnostic (non-fatal) |
| `#line`       | ✅ Source line tracking |
| `#pragma`     | ✅ Silently ignored |
| Null `#`      | ✅ Empty directive |

### Implemented Features

| Feature | Status |
|---------|--------|
| Object-like macro expansion | ✅ |
| Function-like macro expansion | ✅ (basic) |
| `##` token pasting | ✅ |
| `#` stringification | ✅ |
| `__VA_ARGS__` variadic macros | ✅ |
| `defined()` operator | ✅ |
| Expression evaluator | ✅ (full C int constant expr) |
| Backslash-newline joining | ✅ |
| Block (`/* */`) and line (`//`) comments | ✅ |
| Predefined macros | ✅ `__STDC__`, `__FILE__`, `__LINE__`, etc. |
| `-D` / `-U` / `-I` / `-std=` flags | ✅ |
| `-undef` flag | ✅ |

## Building

```sh
cd sic-cpp
make              # builds with ../siccomp/target/release/sic
# or:
SIC=/path/to/sic make
```

## Usage

```sh
./sic-cpp -I/usr/include -DDEBUG=1 input.c > output.i

# Pipe mode:
cat input.c | ./sic-cpp -DNDEBUG
```

## Integration with sic

Set the environment variable `SIC_CPP=sic-cpp` to make the sic compiler use
this preprocessor instead of the system `cpp`:

```sh
SIC_CPP=./sic-cpp/sic-cpp sic -c file.sic
```

The `preprocess.rs` module checks for `SIC_CPP` first, defaulting to `"cpp"`
when unset — so the system preprocessor remains the default.

## Architecture

`src/main.sic` (~1600 lines) is a single self-contained SIC file:

1. **Lexer** — Tokenizes input into preprocessor tokens (identifiers, numbers,
   strings, punctuators), stripping comments.
2. **Macro table** — Flat arrays storing macro definitions. Object-like macros
   store `"O\nbody"`; function-like store `"F\nparams\nbody"`.
3. **Expression evaluator** — Recursive-descent parser for C integer constant
   expressions (`#if` conditions), supporting all C operators including `?:`
   and `defined()`.
4. **Macro expander** — Multi-pass replacement engine with `#` (stringify)
   and `##` (token paste) support.
5. **Directive handler** — Line-oriented dispatch for `#` directives with
   proper conditional compilation stack.
6. **Include handler** — Recursive file inclusion with `""` (current dir
   first) and `<>` (search path) semantics.

## Limitations

- `#embed` (C23) not yet implemented
- Function-like macro argument substitution is basic (no recursive expansion
  of substituted arguments on first pass; blue-paint/disable tracking for
  self-referential macros is partial)
- Line tracking in the output (`#line` directives) is minimal
- `__DATE__` and `__TIME__` use fixed values
