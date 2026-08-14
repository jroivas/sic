# sic ABI plan — aggregate passing / returning

Status: **in progress.** Goal: make sic's C calling convention match the platform
ABI so sic objects interoperate with gcc/clang/glibc, starting with **System V
x86-64** (Linux/BSD/macOS-x64 share the aggregate rules).

## The bug we're fixing

`sic-cranelift/src/types.rs::cl_type` maps every `Struct`/`Union`/`Array` to a
pointer, and `ret_is_sret` (sic-frontend/src/lower/mod.rs) routes every aggregate
return through the hidden sret pointer. So sic passes/returns **all** aggregates by
pointer/sret. SysV instead:

- passes an aggregate **≤16 bytes** (no unaligned/x87 fields) in **registers**
  (per-8-byte "eightbyte", each INTEGER→GPR or SSE→XMM, split allowed);
- passes a larger/unaligned aggregate **by value on the stack** (the "MEMORY" class);
- returns **≤16 bytes** in RAX:RDX / XMM0:XMM1, larger via sret (RAX = ptr).

Consequence today: a gcc caller passing an 8-byte struct/union in a register meets a
sic callee that expects a pointer → **segfault** (confirmed with `run_on_cpu_data`).
All-sic builds are self-consistent so they "work", but can't interop and can't be
gcc/sic object-mix-bisected.

## What Cranelift 0.113 gives us (verified)

Cranelift models the *mechanics*, not the C classification:

- `CallConv::{SystemV, WindowsFastcall, AppleAarch64, Tail, Winch}` — scalar
  register/stack placement per platform, plus `I128` splitting.
- `ArgumentPurpose::StructArgument(size)` — a struct passed **by value on the stack**
  (the SysV MEMORY class). Caller supplies a pointer; Cranelift emits the copy; the
  callee param is a pointer to the copy. **This matches sic's existing pointer
  representation → near drop-in for the >16-byte path.**
- `ArgumentPurpose::StructReturn` — marks the hidden sret pointer so it's returned in
  the platform's sret register (RAX on SysV/Win64, X8 on AArch64).

Cranelift does **not** classify C aggregates (no eightbyte/HFA/Win64 logic — it has
no C struct types). The frontend must classify and, for the register case, marshal
fields ↔ scalar values. This mirrors rustc's `cg_clif` (`abi/pass_mode.rs`).

## Design: isolated classifier (chosen scope)

New module `sic-cranelift/src/abi.rs`, keyed on a `Target` (arch+os), everything
routes through it — no inline ABI magic:

```rust
enum RegClass { Int, Sse }
struct Chunk { class: RegClass, bytes: u32 }      // one eightbyte, bytes ≤ 8
enum ArgClass {
    Direct(Vec<Chunk>),   // → one scalar AbiParam per chunk (I64/I32.. or F64/F32)
    ByValStack(u32),      // → ArgumentPurpose::StructArgument(size)   (SysV MEMORY)
    IndirectByRef,        // Win64/AArch64 large; UNUSED by SysV       (future)
    Ignore,               // empty aggregate
}
enum RetClass { Direct(Vec<Chunk>), Sret }

fn classify_arg(ty: &Type, t: &Target) -> ArgClass
fn classify_ret(ty: &Type, t: &Target) -> RetClass
```

Implement the **SysV** arm now; leave `Win64`/`AArch64` arms as documented
`unimplemented!`. `CallConv` still comes from the host `target_config()` for now.

### SysV classification algorithm (implement in abi.rs)

For a Struct/Union/Array `ty` (scalars keep their current `cl_type` mapping):

1. `size = ty.size_of()`. If `size == 0` → `Ignore`.
2. If `size > 16`, or any field is `Float80` (x87 class), or any field is
   mis-aligned → **MEMORY** → `ByValStack(size)` (arg) / `Sret` (ret).
3. Else classify into `ceil(size/8)` (1 or 2) eightbytes:
   - Recurse fields at their byte offsets. Scalar Int/Bool/Pointer → INTEGER for the
     eightbyte(s) it covers; Float32/Float64 → SSE; nested struct/union/array →
     recurse; arrays → per element.
   - Merge per eightbyte: `NO_CLASS+X→X`, `INTEGER+any→INTEGER`, `SSE+SSE→SSE`.
   - Post-merge SysV fixups (rare, but include): if either eightbyte is MEMORY →
     whole thing MEMORY; the "if one eightbyte is SSEUP without preceding SSE" rule
     only matters for >16B vectors (we punt those to MEMORY).
   - Emit `Chunk{Int, min(8, size-offset)}` or `Chunk{Sse, ...}` per eightbyte.
4. Chunk → AbiParam type: Int→`I64` (or I8/I16/I32 for a <8-byte tail); Sse→`F64`
   (or `F32` for a 4-byte tail).

## Wiring plan (files/functions to change)

The IR already represents every aggregate value as a **pointer** (`lower_aggregate_ptr`),
and `Instr::Call.args` carries that pointer; `FunctionType.params/ret` keep the real
aggregate `Type`. So the backend has both the type (to classify) and a pointer (to
marshal). Changes are backend-only except the sret-return rule.

1. **`abi.rs`** — new: the classifier above + a `Target` struct (host-derived).
2. **`build_cl_sig` / `build_cl_sig_def`** (lib.rs) — per param: `classify_arg` →
   push N scalar AbiParams (Direct), or one `StructArgument(size)` (ByValStack), or
   nothing (Ignore). Return: `classify_ret` → set `cl_sig.returns` to the chunk
   types (Direct) or keep the sret pointer param and mark it `StructReturn` (Sret).
3. **Call lowering** — `Instr::Call` and `Instr::CallIndirect` (func.rs): for a
   Direct aggregate arg, the IR arg is a pointer; **load each chunk** (`load.i64` /
   `load.f64` at chunk offset, partial loads for tails) and pass the loaded scalars
   in place of the pointer. ByValStack → pass the pointer (Cranelift copies). Handle
   the arg-index ↔ AbiParam-index remap (one IR arg may become 0/1/2 CL args).
4. **Callee prologue** (func.rs `compile_function`) — for a Direct aggregate param,
   alloc a stack slot, **store the incoming chunk params** into it, and bind the IR
   param sentinel (`0x10000+i`) to the slot address (the pointer the body expects).
   ByValStack param is already a pointer → bind directly. Keep the va save-area code.
5. **Return lowering** — for a Direct small-aggregate return, load chunks from the
   result pointer and `return` the scalars; the **caller** stores the returned
   scalars into a slot and uses that as the aggregate pointer. `>16B` keeps sret.
6. **`ret_is_sret`** (sic-frontend) — only used by the frontend to prepend the sret
   pointer; change it to sret **only when the return is MEMORY-class** (size>16 /
   Float80 / unaligned). Small-aggregate returns must NOT prepend sret (they return
   in registers). Keep function-pointer type lowering in sync (types.rs:190).

Watch: `enable_llvm_abi_extensions` is already set (needed for I128 etc.); the
variadic save-area path ([[sic-vararg-overflow]]) is SysV-specific — a small
aggregate passed to a variadic call still classifies the same way, just make sure the
va filler params come after the classified fixed params.

## Test plan

- Extend the cross-compiler harness (`/tmp` repro this session): gcc `main` ↔ sic
  callee and vice-versa for: U8 union, S8/S16 structs, `{double,double}`,
  `{int,float}`, `{char[3]}`, a 24-byte struct (MEMORY), small-struct **returns**,
  and a variadic call taking a small struct. Compare against gcc-only reference.
- Add `tests/test_0194.c…` self-checking (compute-through-by-value) cases.
- Rebuild QEMU; re-run the gcc/sic object-mix (`accel/tcg`, `hw/intc`) — the
  `async_run_on_cpu` / small-union segfaults should vanish, unblocking bisection of
  [[qemu-jemmex-async-fault]].

## Portability roadmap (later targets)

When a real second target lands, add the classifier arm + set CallConv from the
triple (`isa::lookup(triple)` instead of `cranelift_native::builder()`):

| Axis | SysV x64 (now) | Win64 | AArch64 (AAPCS64 / Apple) |
|---|---|---|---|
| Aggregate → regs | eightbyte split, ≤16B | only sizeof∈{1,2,4,8}→1 reg; else by-ref | HFA≤4→SIMD; other ≤16B→≤2 X; else by-ref |
| Large aggregate | by value on stack (StructArgument) | by reference (copy+ptr) | by reference |
| Return sret reg | RAX | RAX | X8 |
| Arg regs (int/fp) | 6 / 8 | 4 / 4 + 32B shadow, no red zone | 8 / 8 |
| Variadic | AL = #XMM used | float in GPR **and** XMM | Apple: all varargs on stack |
| `long double` | 80-bit (sic still f64 — TODO) | 64-bit | 128-bit |
| Bitfields | Itanium/GCC rules (implemented) | **MSVC rules differ** | AAPCS rules |
| Symbols | plain | plain (C) | macOS leading `_` |

### Known follow-ups (independent of aggregates)
- `long double`: sic maps Float80→f64; correct SysV is 80-bit x87 (size 16, align
  16). Affects `<math.h>` `long double` interop. Separate fix.
- Target-triple plumbing: replace `cranelift_native::builder()` with
  `isa::lookup(target_lexicon::Triple)` to cross-compile / choose CallConv.
- MSVC bitfield allocation rules when Win64 is added.
