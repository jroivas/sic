// binary-trees (max depth 16) — the Computer Language Benchmarks Game.
// Source: https://benchmarksgame-team.pages.debian.net/benchmarksgame/description/binarytrees.html
// (algorithm as in the single-threaded programs there; revised BSD licence).
// Adapted: single-threaded, Box allocation (no arena), fixed depth; prints the sum
// of every tree check.
struct Node { children: Option<(Box<Node>, Box<Node>)> }

fn bottom_up(depth: i32) -> Box<Node> {
    if depth > 0 {
        Box::new(Node { children: Some((bottom_up(depth - 1), bottom_up(depth - 1))) })
    } else {
        Box::new(Node { children: None })
    }
}

fn check(n: &Node) -> i64 {
    match &n.children { Some((l, r)) => 1 + check(l) + check(r), None => 1 }
}

fn main() {
    let (min_depth, max_depth) = (4, 16);
    let mut total: i64 = 0;
    total += check(&bottom_up(max_depth + 1));
    let long_lived = bottom_up(max_depth);
    let mut d = min_depth;
    while d <= max_depth {
        let iterations = 1 << (max_depth - d + min_depth);
        let mut c = 0;
        for _ in 0..iterations { c += check(&bottom_up(d)); }
        total += c;
        d += 2;
    }
    total += check(&long_lived);
    println!("{}", total);
}
