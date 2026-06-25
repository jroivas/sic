use std::collections::HashSet;
use std::fs;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::process::Command;

use clap::Parser as ClapParser;
use sic_cranelift::CraneliftBackend;
use sic_frontend::{preprocess, Lexer, Parser, Lowerer};
use sic_ir::{Backend, display::print_module};
use sic_opt::ConstFold;

#[derive(ClapParser, Debug)]
#[command(name = "sic", about = "SIC compiler (Rust/Cranelift)")]
struct Args {
    /// Input source file
    filename: String,

    /// Output file
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Emit IR text instead of compiling
    #[arg(short = 'S', long = "emit-ir")]
    emit_ir: bool,

    /// Compile to object file, do not link
    #[arg(short = 'c', long = "emit-obj")]
    emit_obj: bool,

    /// Optimization level (0 = none, 1 = const fold)
    #[arg(short = 'O', long = "opt", default_value = "0")]
    opt: u32,

    /// Preprocessor defines
    #[arg(short = 'D', action = clap::ArgAction::Append, value_name = "MACRO")]
    defines: Vec<String>,

    /// Include directories
    #[arg(short = 'I', action = clap::ArgAction::Append, value_name = "DIR")]
    includes: Vec<String>,

    /// Dump AST
    #[arg(long = "ast")]
    ast: bool,

    /// Enable debug output
    #[arg(short = 'd', long = "debug")]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // ── Preprocess ────────────────────────────────────────────────────────────
    let preprocessed = preprocess(&args.filename, &args.defines, &args.includes)
        .map_err(|e| format!("{}", e))?;

    // ── Lex ───────────────────────────────────────────────────────────────────
    let mut lexer = Lexer::new(&preprocessed, HashSet::new());
    let tokens = lexer.tokenize().map_err(|e| format!("{}", e))?;

    // ── Parse ─────────────────────────────────────────────────────────────────
    let mut parser = Parser::new(tokens, args.filename.clone());
    let mut tu = parser.parse().map_err(|e| format!("{}", e))?;

    if args.ast {
        eprintln!("{:#?}", tu);
    }

    // ── Optimize ──────────────────────────────────────────────────────────────
    if args.opt >= 1 {
        ConstFold::fold_tu(&mut tu);
    }

    // ── Lower to IR ───────────────────────────────────────────────────────────
    let module_name = PathBuf::from(&args.filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("module")
        .to_string();

    let lowerer = Lowerer::new(module_name);
    let ir_module = lowerer.lower(&tu).map_err(|e| format!("{}", e))?;

    if args.debug {
        eprintln!("{}", print_module(&ir_module));
    }

    // ── Emit IR ───────────────────────────────────────────────────────────────
    if args.emit_ir {
        let ir_text = print_module(&ir_module);
        if let Some(out) = &args.output {
            fs::write(out, &ir_text)?;
        } else {
            print!("{}", ir_text);
        }
        return Ok(());
    }

    // ── Codegen ───────────────────────────────────────────────────────────────
    let mut backend = CraneliftBackend::new();
    let obj_bytes = backend.compile_module(&ir_module)
        .map_err(|e| format!("codegen error: {}", e))?;

    // ── Emit object ──────────────────────────────────────────────────────────
    if args.emit_obj {
        let obj_path = args.output.as_deref().unwrap_or_else(|| {
            // default: foo.c → foo.o
            Box::leak(
                PathBuf::from(&args.filename)
                    .with_extension("o")
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str()
            )
        });
        fs::write(obj_path, &obj_bytes)?;
        return Ok(());
    }

    // ── Link ─────────────────────────────────────────────────────────────────
    let out_path = args.output.as_deref().unwrap_or("a.out");

    // Write object to a temp file
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(&obj_bytes)?;
    let tmp_path = tmp.path().to_owned();
    // Keep the temp file open until after linking
    drop(tmp); // close file but it'll be cleaned up by NamedTempFile drop

    // Actually we need to keep it alive:
    let mut tmp2 = tempfile::Builder::new().suffix(".o").tempfile()?;
    tmp2.write_all(&obj_bytes)?;
    let tmp_obj = tmp2.path().to_owned();

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let status = Command::new(&cc)
        .arg(tmp_obj.as_os_str())
        .arg("-o")
        .arg(out_path)
        .arg("-lm")
        .status()?;

    if !status.success() {
        return Err(format!("linker failed with exit code {:?}", status.code()).into());
    }

    Ok(())
}
