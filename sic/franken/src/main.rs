//! franken-SIC: the sic command (siccomp's driver, as a library) with the
//! stages `SIC_PARTS` names running in SIC. `-print-parts` lists the stages.
//! See sic/PLAN.md.

#[cfg(sic_lexer)]
mod lexer;
mod parts;

fn main() {
    let active = match parts::active(std::env::var("SIC_PARTS").ok().as_deref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sic: error: SIC_PARTS: {}", e);
            std::process::exit(2);
        }
    };
    if std::env::args().skip(1).any(|a| a == "-print-parts") {
        parts::print(&active);
        return;
    }
    sic::main_with(parts::stages(&active));
}
