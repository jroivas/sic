//! A crate exercising what `cargo sic` binds automatically.
use std::fmt;

/// Upper-case a string.
pub fn shout<S: AsRef<str>>(s: S) -> String {
    s.as_ref().to_uppercase()
}

/// The sum of the bytes.
pub fn checksum(data: impl AsRef<[u8]>) -> u32 {
    data.as_ref().iter().map(|&b| b as u32).sum()
}

pub const LIMIT: u32 = 10;

pub mod text {
    /// Words, split on whitespace.
    pub fn words(s: &str) -> Vec<&str> {
        s.split_whitespace().collect()
    }
    /// Characters as an iterator.
    pub fn letters(s: &str) -> impl Iterator<Item = char> + '_ {
        s.chars().filter(|c| c.is_alphabetic())
    }
}

#[derive(Debug)]
pub struct ParseError {
    pub at: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "parse error at {}", self.at)
    }
}

/// Only `Debug`: its error text comes from `{:?}`.
#[derive(Debug)]
pub struct Opaque;

/// A semantic version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub label: String,
}

impl Version {
    pub fn parse(s: &str) -> Result<Version, ParseError> {
        let mut it = s.split('.');
        let major = it.next().and_then(|x| x.parse().ok()).ok_or(ParseError { at: 0 })?;
        let minor = it.next().and_then(|x| x.parse().ok()).ok_or(ParseError { at: 1 })?;
        Ok(Version { major, minor, label: String::new() })
    }
    /// A builder that consumes `self` (bound through `Clone`).
    pub fn with_label(mut self, l: &str) -> Version {
        self.label = l.to_string();
        self
    }
    /// A builder returning `&mut Self` (bound as returning nothing).
    pub fn bump(&mut self) -> &mut Self {
        self.minor += 1;
        self
    }
    pub fn newer_than(&self, other: &Version) -> bool {
        self > other
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if !self.label.is_empty() { write!(f, "-{}", self.label)?; }
        Ok(())
    }
}

pub fn strict(s: &str) -> Result<u64, Opaque> {
    s.parse().map_err(|_| Opaque)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Color {
    Red,
    Green,
    Rgb(u8, u8, u8),
}

/// A trait of the crate: its methods (provided ones too) bind on each type.
pub trait Describe {
    fn name(&self) -> String;
    fn describe(&self) -> String {
        format!("<{}>", self.name())
    }
}

impl Describe for Color {
    fn name(&self) -> String {
        format!("{:?}", self)
    }
}

/// A generic pair (bound as `IntPair`).
#[derive(Clone)]
pub struct Pair<T> {
    pub a: T,
    pub b: T,
}

impl<T: Clone + PartialOrd> Pair<T> {
    pub fn new(a: T, b: T) -> Self {
        Pair { a, b }
    }
    pub fn max(&self) -> T {
        if self.a > self.b { self.a.clone() } else { self.b.clone() }
    }
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.a, &mut self.b);
    }
    pub fn first(&self) -> &T {
        &self.a
    }
}

/// A generic stack (bound as `StrStack`).
#[derive(Default)]
pub struct Stack<T> {
    items: Vec<T>,
}

impl<T> Stack<T> {
    pub fn new() -> Self {
        Stack { items: Vec::new() }
    }
    pub fn push(&mut self, x: T) {
        self.items.push(x);
    }
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }
    pub fn peek(&self) -> Option<&T> {
        self.items.last()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }
    pub fn items(&self) -> impl Iterator<Item = &T> {
        self.items.iter().rev()
    }
}

// Not bound: generic over an unconvertible bound.
pub fn ident<T: Copy>(x: T) -> T {
    x
}
