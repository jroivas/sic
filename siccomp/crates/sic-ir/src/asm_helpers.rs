//! Machine code for the inline-asm helpers (x86-64 SysV). Cranelift has no
//! inline assembly, so the frontend lowers each recognised GNU `asm` template
//! to a call of one of these tiny functions, and the backend emits the bytes
//! as a module-local function. Bytes were produced by GNU `as` from:
//!
//! ```text
//! rdtsc:   rdtsc; shl $32,%rdx; or %rdx,%rax; ret                  u64 ()
//! rdtscp:  rdtscp; shl $32,%rdx; or %rdx,%rax; ret                 u64 ()
//! cpuid:   push %rbx; mov %edi,%eax; mov %esi,%ecx; mov %rdx,%r8; cpuid;
//!          mov %eax,(%r8); mov %ebx,4(%r8); mov %ecx,8(%r8);
//!          mov %edx,12(%r8); pop %rbx; ret                        void (u32 leaf, u32 sub, u32 out[4])
//! xgetbv:  mov %edi,%ecx; xgetbv; shl $32,%rdx; or %rdx,%rax; ret  u64 (u32)
//! pause:   pause; ret        barrier: ret
//! mfence/lfence/sfence: <fence>; ret
//! divq:    mov %rdx,%r8; mov %rdi,%rax; mov %rsi,%rdx; div %r8;
//!          mov %rdx,(%rcx); ret                                    u64 (u64 lo, u64 hi, u64 d, u64 *rem)
//! shld:    mov %edx,%ecx; mov %rdi,%rax; shld %cl,%rsi,%rax; ret   u64 (u64 dst, u64 src, u32 cnt)
//! shrd:    (same with shrd)
//! ldqa/ldqu: vmovdq{a,u} (%rsi),%xmm0; vmovdqu %xmm0,(%rdi); ret   void (void *dst, void *src)
//! stqa/stqu: vmovdqu (%rsi),%xmm0; vmovdq{a,u} %xmm0,(%rdi); ret   void (void *dst, void *src)
//! trap:    ud2               (an unsupported asm statement was executed)
//! ```

/// Symbol prefix of every helper (`__sic_asm_rdtsc`, …).
pub const ASM_HELPER_PREFIX: &str = "__sic_asm_";

/// The machine code of helper `name` (full symbol name), if it is one.
pub fn asm_helper_code(name: &str) -> Option<&'static [u8]> {
    Some(match name.strip_prefix(ASM_HELPER_PREFIX)? {
        "rdtsc" => &[0x0f, 0x31, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3],
        "rdtscp" => &[0x0f, 0x01, 0xf9, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3],
        "cpuid" => &[0x53, 0x89, 0xf8, 0x89, 0xf1, 0x49, 0x89, 0xd0, 0x0f, 0xa2, 0x41, 0x89, 0x00, 0x41, 0x89, 0x58, 0x04, 0x41, 0x89, 0x48, 0x08, 0x41, 0x89, 0x50, 0x0c, 0x5b, 0xc3],
        "xgetbv" => &[0x89, 0xf9, 0x0f, 0x01, 0xd0, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3],
        "pause" => &[0xf3, 0x90, 0xc3],
        "barrier" => &[0xc3],
        "mfence" => &[0x0f, 0xae, 0xf0, 0xc3],
        "lfence" => &[0x0f, 0xae, 0xe8, 0xc3],
        "sfence" => &[0x0f, 0xae, 0xf8, 0xc3],
        "divq" => &[0x49, 0x89, 0xd0, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf2, 0x49, 0xf7, 0xf0, 0x48, 0x89, 0x11, 0xc3],
        "shld" => &[0x89, 0xd1, 0x48, 0x89, 0xf8, 0x48, 0x0f, 0xa5, 0xf0, 0xc3],
        "shrd" => &[0x89, 0xd1, 0x48, 0x89, 0xf8, 0x48, 0x0f, 0xad, 0xf0, 0xc3],
        "ldqa" => &[0xc5, 0xf9, 0x6f, 0x06, 0xc5, 0xfa, 0x7f, 0x07, 0xc3],
        "ldqu" => &[0xc5, 0xfa, 0x6f, 0x06, 0xc5, 0xfa, 0x7f, 0x07, 0xc3],
        "stqa" => &[0xc5, 0xfa, 0x6f, 0x06, 0xc5, 0xf9, 0x7f, 0x07, 0xc3],
        "stqu" => &[0xc5, 0xfa, 0x6f, 0x06, 0xc5, 0xfa, 0x7f, 0x07, 0xc3],
        "trap" => &[0x0f, 0x0b],
        _ => return None,
    })
}
