//! The sic **standard library** (`import std;`), written in SIC and shipped with
//! the compiler. It is an ordinary sic module (`module std;`), compiled to its own
//! object and linked in only when a unit says `import std;` (see the driver). It is
//! NOT part of every program and is NOT special to the compiler — `std.Fmt(a, b)`
//! is a normal call to the SIC function below, and all formatting is done in SIC
//! (dispatching on `type(arg).kind` + native `.str`).
//!
//! `Fmt(fmt, args)` builds a formatted string; `Print`/`Println` format then write.
//! `args` is a `va_array` — the trailing call arguments boxed as `any` (the caller
//! packs them). The compiler knows the exported signatures (`resolve_import`), so
//! this source only needs to define them under `module std;` (symbols `std_*`).

/// The std library source, in SIC. Compiled to a separate object and linked when
/// `import std;` is present.
pub const STD_SIC: &str = r#"
module std;

extern int snprintf(char *s, unsigned long n, char *fmt, ...);
extern long write(int fd, void *buf, unsigned long n);

// One boxed argument formatted as an OWNED native string. Built by concatenation
// (`x + ""`) so the result owns its bytes — a view of a local buffer would dangle.
// Dispatch on the value's runtime kind (see the compiler's `type_kind`).
static string arg_str(any x) {
    u32 k = type(x).kind;
    // `s + ""` forces an OWNED copy (a view of a local buffer would dangle). A
    // `char*` is first bound to a `string` (a view) so `+` reads it as a string,
    // not pointer arithmetic.
    if (k == 9) return (string)x + "";                                              // STR
    if (k == 8) { string sc = (char *)x; return sc + ""; }                          // CSTR
    // `.str` on bigint/fixed is auto-freed at scope exit (do NOT free it here); the
    // `+ ""` makes an owned copy that outlives this function.
    if (k == 16) { char *s = ((bigint)x).str; string ss = s; return ss + ""; } // BIGINT
    if (k == 10) { char *s = ((fixed)x).str; string ss = s; return ss + ""; }  // FIXED
    if (k == 1) { if ((bool)x) return "true"; return "false"; }                      // BOOL
    if (k == 2) { char b[32]; snprintf(b, 32, "%lld", (long long)(i64)x); string sb = b; return sb + ""; }        // INT
    if (k == 3) { char b[32]; snprintf(b, 32, "%llu", (unsigned long long)(u64)x); string sb = b; return sb + ""; } // UINT
    if (k == 4 || k == 5 || k == 6) { char b[64]; snprintf(b, 64, "%g", (double)x); string sb = b; return sb + ""; } // FLOAT
    if (k == 7) { char b[32]; snprintf(b, 32, "%p", (void *)x); string sb = b; return sb + ""; }       // PTR
    return "<?>";
}

// `Fmt("… {} …", a, b)` — `{}` placeholders (Python/Rust-style; `{{`/`}}` are
// literal braces), each substituted by the next argument formatted by its type.
string Fmt(string fmt, va_array args) {
    string result = "";
    char *f = fmt.ptr;
    u64 n = fmt.size;      // byte length
    u64 i = 0;
    u64 ai = 0;
    while (i < n) {
        char c = f[i];
        if (c == 123 && i + 1 < n && f[i + 1] == 123) { result = result + "{"; i = i + 2; }       // {{
        else if (c == 125 && i + 1 < n && f[i + 1] == 125) { result = result + "}"; i = i + 2; }  // }}
        else if (c == 123 && i + 1 < n && f[i + 1] == 125) {                                        // {}
            if (ai < args.length) { result = result + arg_str(args[ai]); ai = ai + 1; }
            i = i + 2;
        } else {
            char one[2]; one[0] = c; one[1] = 0; char *op = one; result = result + op; i = i + 1;
        }
    }
    return result;
}

// `Print(a, b, …)` — format each argument (no format string) and write to stdout.
int Print(va_array args) {
    string s = "";
    u64 i = 0;
    while (i < args.length) { s = s + arg_str(args[i]); i = i + 1; }
    write(1, s.ptr, s.size);
    return 0;
}

int Println(va_array args) {
    string s = "";
    u64 i = 0;
    while (i < args.length) { s = s + arg_str(args[i]); i = i + 1; }
    s = s + "\n";
    write(1, s.ptr, s.size);
    return 0;
}
"#;
