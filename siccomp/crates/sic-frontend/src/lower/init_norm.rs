//! C brace elision (C11 6.7.9p20): rewrite an initializer list whose inner
//! braces are omitted into the fully braced form both lowering paths handle.
//!
//! `struct { int x; struct { int a, b; } in; int y; } v = {1, 2, 3, 4};` is
//! `{1, {2, 3}, 4}`; `int m[2][2] = {1, 2, 3, 4}` is `{{1, 2}, {3, 4}}`. A
//! bare (non-brace) value whose slot is an aggregate starts an elided
//! sub-aggregate that takes as many following values as it has members; a
//! designator ends an elided sub-aggregate (it names a member of the braced
//! object). A braced list is normalized recursively. An already fully braced
//! list comes back unchanged (modulo explicit `.field` designators).
//!
//! Named struct members get an explicit `.field` designator in the output so
//! the downstream positional cursor cannot drift (unnamed bit-fields, which a
//! positional value skips, sit between them).

use std::collections::HashMap;
use crate::ast::{Designator, Expr, ExprKind, InitItem, Initializer};
use sic_ir::Type;
use super::types::resolve_aggregate;

pub(crate) struct InitNorm<'a> {
    pub named: &'a HashMap<String, Type>,
    pub enum_consts: &'a HashMap<String, i64>,
    /// `T` takes part in brace elision (a C struct/union/array — not a sic
    /// built-in carried as a struct, such as `string` or a tagged enum).
    pub plain_aggregate: &'a dyn Fn(&Type) -> bool,
    /// The expression is itself a whole aggregate value for slot `T` (a struct
    /// variable, a call, a compound literal), so it is not elided into.
    pub is_aggregate_value: &'a dyn Fn(&Expr, &Type) -> bool,
}

/// One member slot of an aggregate.
struct Slot { name: Option<String>, ty: Type }

impl<'a> InitNorm<'a> {
    /// Normalize the braced list `items` initializing an object of type `ty`.
    pub fn braced(&self, ty: &Type, items: &[InitItem]) -> Vec<InitItem> {
        let rty = resolve_aggregate(ty, self.named);
        if !(self.plain_aggregate)(&rty) { return items.to_vec(); }
        let slots = self.slots(&rty);
        let count = self.slot_count(&rty, &slots);
        let mut out = Vec::with_capacity(items.len());
        let mut cursor = 0usize;
        let mut i = 0usize;
        while i < items.len() {
            let item = &items[i];
            if !item.designators.is_empty() {
                // `.f = v` / `[k] = v`: a single designator names the slot (and may
                // start an elided sub-aggregate there); a chain passes through.
                let idx = match &item.designators[0] {
                    Designator::Field(n) => match &rty {
                        Type::Struct(_) | Type::Union(_) =>
                            slots.iter().position(|s| s.name.as_deref() == Some(n.as_str())),
                        _ => None,
                    },
                    Designator::Index(e) => super::eval_const_expr(e, self.enum_consts).ok()
                        .filter(|&k| k >= 0).map(|k| k as usize),
                    Designator::IndexRange(..) => None,
                };
                let Some(idx) = idx else {
                    // Unresolvable here (a member of an anonymous member, a range):
                    // leave this and the rest as written.
                    out.extend_from_slice(&items[i..]);
                    return out;
                };
                if item.designators.len() > 1 {
                    out.push(item.clone());
                    i += 1;
                } else {
                    let sty = self.slot_type(&rty, &slots, idx);
                    let init = self.value(&sty, items, &mut i);
                    out.push(InitItem { designators: item.designators.clone(), init });
                }
                cursor = idx + 1;
                continue;
            }
            if count.map_or(false, |c| cursor >= c) {
                // Excess elements: as written (lowering ignores / diagnoses them).
                out.extend_from_slice(&items[i..]);
                return out;
            }
            let sty = self.slot_type(&rty, &slots, cursor);
            let init = self.value(&sty, items, &mut i);
            out.push(InitItem { designators: self.slot_designator(&rty, &slots, cursor), init });
            cursor += 1;
        }
        out
    }

    /// The initializer for one slot of type `ty` starting at `items[*i]`,
    /// consuming the items it uses.
    fn value(&self, ty: &Type, items: &[InitItem], i: &mut usize) -> Initializer {
        let rty = resolve_aggregate(ty, self.named);
        let item = &items[*i];
        match &item.init {
            Initializer::List(sub) => {
                *i += 1;
                if (self.plain_aggregate)(&rty) {
                    Initializer::List(self.braced(&rty, sub))
                } else {
                    item.init.clone()
                }
            }
            Initializer::Expr(e) => {
                if !(self.plain_aggregate)(&rty) || self.direct_value(e, &rty) {
                    *i += 1;
                    return item.init.clone();
                }
                // Brace elision: this aggregate takes the following values.
                let start = *i;
                let sub = self.elided(&rty, items, i);
                if *i == start {
                    // Nothing to fill (an empty aggregate): keep the value as is.
                    *i += 1;
                    return item.init.clone();
                }
                Initializer::List(sub)
            }
        }
    }

    /// An aggregate initialized without its braces, from `items[*i..]`: fill
    /// its slots in order until they run out, the values run out, or a
    /// designator (which belongs to the enclosing braced object) appears.
    fn elided(&self, rty: &Type, items: &[InitItem], i: &mut usize) -> Vec<InitItem> {
        let slots = self.slots(rty);
        let count = self.slot_count(rty, &slots);
        let mut out = Vec::new();
        let mut k = 0usize;
        while *i < items.len() && count.map_or(true, |c| k < c) && items[*i].designators.is_empty() {
            let sty = self.slot_type(rty, &slots, k);
            let init = self.value(&sty, items, i);
            out.push(InitItem { designators: self.slot_designator(rty, &slots, k), init });
            k += 1;
        }
        out
    }

    /// `e` initializes a whole slot of aggregate type `ty` directly.
    fn direct_value(&self, e: &Expr, ty: &Type) -> bool {
        match ty {
            // `char s[N]` from a string literal.
            Type::Array { elem, .. }
                if matches!(elem.as_ref(), Type::Int { bits: 8, .. })
                    && matches!(&e.kind, ExprKind::StringLit(_)) => true,
            // `wchar_t s[N]` from a wide string literal.
            Type::Array { elem, .. }
                if matches!(elem.as_ref(), Type::Int { bits: 16 | 32, .. })
                    && matches!(&e.kind, ExprKind::WideStringLit(..)) => true,
            _ => (self.is_aggregate_value)(e, ty),
        }
    }

    /// The member slots of a struct or union, in initialization order: a
    /// struct's fields minus unnamed bit-fields (a positional value skips
    /// them), a union's members. Arrays have no named slots (see `slot_count`).
    fn slots(&self, rty: &Type) -> Vec<Slot> {
        let slot = |n: &String, t: &Type| Slot { name: if n.is_empty() { None } else { Some(n.clone()) }, ty: t.clone() };
        match rty {
            Type::Struct(st) => st.fields.iter().enumerate()
                .filter(|(idx, (n, _))| !(n.is_empty() && matches!(st.bitfields.get(*idx), Some(Some(_)))))
                .map(|(_, (n, t))| slot(n, t))
                .collect(),
            Type::Union(u) => u.fields.iter().map(|(n, t)| slot(n, t)).collect(),
            _ => Vec::new(),
        }
    }

    /// How many positional values the aggregate takes; None = unbounded (an
    /// array of unknown length). A union takes one.
    fn slot_count(&self, rty: &Type, slots: &[Slot]) -> Option<usize> {
        match rty {
            Type::Array { len: 0, .. } => None,
            Type::Array { len, .. } => Some(*len),
            Type::Union(_) => Some(slots.len().min(1)),
            _ => Some(slots.len()),
        }
    }

    fn slot_type(&self, rty: &Type, slots: &[Slot], idx: usize) -> Type {
        match rty {
            Type::Array { elem, .. } => (**elem).clone(),
            _ => slots.get(idx).map(|s| s.ty.clone()).unwrap_or(Type::Void),
        }
    }

    /// `.name` for a named struct member (keeps the downstream cursor exact);
    /// positional for array elements, union members and anonymous members.
    fn slot_designator(&self, rty: &Type, slots: &[Slot], idx: usize) -> Vec<Designator> {
        match rty {
            Type::Struct(_) => match slots.get(idx).and_then(|s| s.name.clone()) {
                Some(n) => vec![Designator::Field(n)],
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}
