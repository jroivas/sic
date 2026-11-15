//! The C integer kind of a type or expression where sic's IR type does not
//! tell it: `long` and `long long` are both an `i64` (`int` and `long` both an
//! `i32` on i386), but `_Generic` and `__builtin_types_compatible_p` tell them
//! apart (C 6.2.7: different types). Unknown is `None`, and the IR type alone
//! decides, as before.
use std::cell::RefCell;
use sic_ir::fast_hash::HashMap;
use crate::ast::AstType;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum IntKind { Int, Long, LongLong }

/// An integer kind under `depth` pointers (`long **` is `(2, Long)`): `long *`
/// and `long long *` are one IR type too.
pub(crate) type Kind = (u8, IntKind);

thread_local! {
    /// Integer typedefs by name: `int64_t` is a `long`.
    static TYPEDEF_KINDS: RefCell<HashMap<String, Kind>> = RefCell::new(HashMap::default());
    /// Each function's declared return type, resolved when asked (its typedefs
    /// may come later in the unit).
    static FN_RETURNS: RefCell<HashMap<String, AstType>> = RefCell::new(HashMap::default());
}

/// Forget the typedefs and functions (start of a translation unit).
pub(crate) fn clear() {
    TYPEDEF_KINDS.with(|m| m.borrow_mut().clear());
    FN_RETURNS.with(|m| m.borrow_mut().clear());
}

/// Function `name` returns `ret`.
pub(crate) fn note_function(name: &str, ret: &AstType) {
    FN_RETURNS.with(|m| { m.borrow_mut().insert(name.to_string(), ret.clone()); });
}

/// The kind function `name` returns.
pub(crate) fn function_kind(name: &str) -> Option<Kind> {
    FN_RETURNS.with(|m| m.borrow().get(name).and_then(ast_kind))
}

/// Typedef `name` stands for `ty`: remember its kind (another typedef of the
/// name, of no integer kind, forgets it).
pub(crate) fn note_typedef(name: &str, ty: &AstType) {
    let k = ast_kind(ty);
    TYPEDEF_KINDS.with(|m| {
        let mut m = m.borrow_mut();
        match k { Some(k) => { m.insert(name.to_string(), k); } None => { m.remove(name); } }
    });
}

/// The kind a written type names, through typedefs; an array is the pointer
/// it decays to.
pub(crate) fn ast_kind(ty: &AstType) -> Option<Kind> {
    match ty {
        AstType::Int { .. } => Some((0, IntKind::Int)),
        AstType::Long { .. } => Some((0, IntKind::Long)),
        AstType::LongLong { .. } => Some((0, IntKind::LongLong)),
        AstType::Named(n) => TYPEDEF_KINDS.with(|m| m.borrow().get(n).copied()),
        AstType::Pointer { base, .. } | AstType::Array { base, vector: false, .. } =>
            ast_kind(&base.ty).map(|(d, k)| (d + 1, k)),
        _ => None,
    }
}

/// Whether two types of one IR type are different C types: both kinds known
/// and not the same.
pub(crate) fn differ(a: Option<Kind>, b: Option<Kind>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x != y)
}
