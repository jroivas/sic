// Binary search tree — 1M inserts then 1M lookups.
// Uses Box allocation for heap nodes with iterative insertion.

struct BstNode {
    key: u32,
    left: Option<Box<BstNode>>,
    right: Option<Box<BstNode>>,
}

fn main() {
    const M: usize = 1000000;
    const Q: usize = 1000000;
    let mut root: Option<Box<BstNode>> = None;
    let mut x: u32 = 22222;
    for _ in 0..M {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let key = x & 0x7FFFFFFF;
        let mut cur = &mut root;
        loop {
            match cur {
                None => {
                    *cur = Some(Box::new(BstNode { key, left: None, right: None }));
                    break;
                }
                Some(node) => cur = if key < node.key { &mut node.left } else { &mut node.right },
            }
        }
    }
    let mut y: u32 = 99991;
    let mut cs: u32 = 0;
    for _ in 0..Q {
        y = y.wrapping_mul(1664525).wrapping_add(1013904223);
        let key = y & 0x7FFFFFFF;
        let mut steps: u32 = 0;
        let mut cur = &root;
        while let Some(node) = cur {
            steps = steps.wrapping_add(1);
            if key == node.key {
                break;
            }
            cur = if key < node.key { &node.left } else { &node.right };
        }
        cs = cs.wrapping_mul(1000003).wrapping_add(steps);
    }
    println!("checksum {}", cs);
}