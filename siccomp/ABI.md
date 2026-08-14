# sic ABI compliance — remaining work

This lists what is **left to reach full ABI compliance**, i.e. the steps *after* the
current task (System V x86-64 aggregate passing/returning in registers). The current
task is tracked in commit history / the `sic-small-aggregate-abi` note; once it lands,
sic objects interoperate with gcc/clang/glibc for by-value structs on Linux x86-64.
Everything below is still open.

All items should plug into the isolated-classifier design (`abi.rs`:
`classify_arg`/`classify_ret` + a `Target`), so adding a platform = adding an arm,
not scattering ABI logic.

## 1. Finish System V x86-64 (same platform, remaining gaps)
- [ ] **`long double`**: sic maps `Float80` → `f64`. SysV needs true 80-bit x87
      (size 16, align 16), returned in ST0, and forcing MEMORY class inside
      aggregates. Blocks correct `<math.h>` / `long double` interop. (Cranelift has
      no f80 — needs soft-float or x87 handling.)
- [ ] **`_Complex` float/double/long double**: SysV passes as two SSE / an x87 pair;
      verify sic's representation and passing.
- [ ] **Vector/SIMD types** (`__m128`/`__m256`, `vector_size`): SSE/AVX arg classes,
      16/32-byte alignment, register passing. sic emulates vectors as aggregates —
      confirm ABI passing matches (esp. once small aggregates go in regs).
- [ ] **Bit-fields**: layout follows Itanium/GCC (implemented); double-check passing
      of aggregates containing bit-fields through the new classifier.
- [ ] Confirm `__int128` **return** (RAX:RDX) and variadic small-aggregate + AL count.

## 2. Target plumbing (prerequisite for any non-host target)
- [ ] Replace `cranelift_native::builder()` with `isa::lookup(target_lexicon::Triple)`
      so a triple can be selected; derive `CallConv` and data-layout from it.
- [ ] Per-target **data layout** table (pointer size, `long double`, alignments)
      instead of host-implicit values.
- [ ] **Object format**: currently ELF via `cranelift-object`. macOS = Mach-O,
      Windows = COFF/PE.
- [ ] **Symbol decoration**: macOS prepends `_`; keep plain on Linux/Win64-C.
- [ ] **TLS model** per platform (currently hard-coded `elf_gd`; also need
      le/ie/local-dynamic, and Mach-O / Windows TLS).

## 3. Windows x64 (`CallConv::WindowsFastcall`)
- [ ] Classifier arm: aggregate of size ∈ {1,2,4,8} → one register; any other size →
      **by reference** (caller copies, passes pointer). Never split.
- [ ] 4 int / 4 fp arg registers; **32-byte shadow space**; **no red zone**.
- [ ] Return: {1,2,4,8} → RAX, else sret pointer (RAX).
- [ ] **Variadic**: float args duplicated into GPR **and** XMM; `va_list` is a plain
      pointer, not the SysV register-save struct → per-target `va_start`/`va_arg`.
- [ ] **MSVC bit-field** allocation rules (differ from Itanium).
- [ ] SEH unwind info (if needed); COFF symbol decoration.

## 4. AArch64 — AAPCS64, Apple, and Windows-ARM sub-variants
- [ ] Classifier arm: **HFA/HVA** (≤4 homogeneous float/vector members) → consecutive
      SIMD regs; other aggregates ≤16 B → up to 2 X regs; >16 B → by reference.
- [ ] sret pointer in **X8** (not RAX).
- [ ] `long double` = **128-bit** IEEE quad.
- [ ] `char` is **unsigned** by default → default-char-signedness must be per-target.
- [ ] **Variadic**: Apple passes *all* varargs on the stack (and packs sub-8B args);
      standard AAPCS64 uses a reg-save area; Windows-ARM differs again → three
      `va_list`/`va_start` variants.
- [ ] Mach-O + leading `_` on Apple.

## 5. 32-bit targets (i386 / ARM32) — only if targeted
- [ ] Pointer size 4; distinct data layout (`double` align 4 on i386-Linux; i386
      `long double` = 96-bit).
- [ ] i386 cdecl: aggregates passed on the stack; small-struct **return** is
      EAX:EDX vs hidden pointer and *differs Linux vs Windows*.
- [ ] Separate `va_list` / stack-arg rules.

## 6. Cross-cutting correctness (every target)
- [ ] Default **`char` / enum signedness** per platform (ARM unsigned char, etc.).
- [ ] `max_align_t` / heap alignment assumptions.
- [ ] Stack alignment (16 B at call) verified per target; frame-pointer/red-zone
      rules.
- [ ] **Endianness** (only if a big-endian target is added): struct byte order and
      bit-field bit order.
- [ ] Unwind/`setjmp` interop: DWARF CFI (SysV) vs SEH (Windows).
- [ ] Inline-asm constraints per architecture.

## Where each plugs in
| Concern | Hook |
|---|---|
| aggregate reg/ref/stack rules | `classify_arg` / `classify_ret` arm |
| calling convention | `CallConv` from the triple |
| variadic | per-target `va_start` / `va_arg` / `va_list` |
| scalar sizes (`long double`, pointer) | `Target` data-layout |
| symbols / TLS / object format | backend/module setup from the triple |
