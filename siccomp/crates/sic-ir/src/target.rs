//! The target a compilation is for: x86-64 (the default) or i386 (`-m32`, with
//! the LLVM back end). Set once by the driver, before preprocessing; the
//! predefined macros and every type size follow it.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static PTR_SIZE: AtomicU32 = AtomicU32::new(8);
static SHORT_WCHAR: AtomicBool = AtomicBool::new(false);

/// Compile for i386 (`-m32`): 4-byte pointers, `long` and `size_t`.
pub fn set_i386() { PTR_SIZE.store(4, Ordering::Relaxed); }

/// The target's pointer size in bytes.
pub fn ptr_size() -> u32 { PTR_SIZE.load(Ordering::Relaxed) }

/// Whether the target is i386.
pub fn is_i386() -> bool { ptr_size() == 4 }

/// `-fshort-wchar` (Linux, EFI): `wchar_t` and `L"…"` are `unsigned short`.
pub fn set_short_wchar(on: bool) { SHORT_WCHAR.store(on, Ordering::Relaxed); }

/// Whether `wchar_t` is 16 bits (`-fshort-wchar`) rather than `int`.
pub fn short_wchar() -> bool { SHORT_WCHAR.load(Ordering::Relaxed) }
