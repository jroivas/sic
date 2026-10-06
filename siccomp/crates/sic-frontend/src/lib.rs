pub mod preprocess;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod lower;
pub mod module_manifest;

pub use preprocess::{preprocess, preprocess_ex, preprocessor_bin};
pub use lexer::{Lexer, Lang};
pub use parser::Parser;
pub use lower::Lowerer;
pub use module_manifest::{ModuleManifest, Export as ManifestExport};

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub file: Option<String>,
    pub line: u32,
    pub col: u32,
}

impl CompileError {
    pub fn new(msg: impl Into<String>) -> Self {
        CompileError { message: msg.into(), file: None, line: 0, col: 0 }
    }
    pub fn at(msg: impl Into<String>, file: Option<String>, line: u32, col: u32) -> Self {
        CompileError { message: msg.into(), file, line, col }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}:{}:{}: error: {}", file, self.line, self.col, self.message)
        } else if self.line > 0 {
            write!(f, "line {}:{}: error: {}", self.line, self.col, self.message)
        } else {
            write!(f, "error: {}", self.message)
        }
    }
}

impl std::error::Error for CompileError {}

pub type Result<T> = std::result::Result<T, CompileError>;
