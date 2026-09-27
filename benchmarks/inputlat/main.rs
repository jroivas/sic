fn il_push(hd: &mut [u32; 8192], hc: &mut [u32; 8192], hg: &mut [u32; 8192], hn: u32,
           d: u32, c: u32, g: u32) -> u32 {
    let mut i = hn as usize;
    hd[i] = d;
    hc[i] = c;
    hg[i] = g;
    while i > 0 {
        let p = (i - 1) / 2;
        if hd[p] <= hd[i] {
            break;
        }
        hd.swap(p, i);
        hc.swap(p, i);
        hg.swap(p, i);
        i = p;
    }
    hn + 1
}

fn il_hit(mx: u32, my: u32, wx: &[u32; 1024], wy: &[u32; 1024], ww: &[u32; 1024],
          wh: &[u32; 1024], gstart: &[u32; 161], gitems: &[u32; 10240]) -> u32 {
    let c = ((my / 80) * 16 + mx / 80) as usize;
    let mut k = gstart[c + 1];
    while k > gstart[c] {
        k -= 1;
        let i = gitems[k as usize] as usize;
        if mx >= wx[i] && mx < wx[i] + ww[i] && my >= wy[i] && my < wy[i] + wh[i] {
            return i as u32;
        }
    }
    1024
}

fn il_bubble(hit: u32, wflags: &[u32; 1024], wparent: &[u32; 1024]) -> u32 {
    if hit >= 1024 {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut node = hit as usize;
    loop {
        acc = acc.wrapping_mul(31).wrapping_add(wflags[node]);
        if node == 0 {
            break;
        }
        node = wparent[node] as usize;
    }
    acc
}

fn bench_inputlat() {
    const EVENTS: u32 = 1000000;
    const ROUNDS: usize = 20;
    const FRAME_US: u32 = 4000;
    const PROC_US: u32 = 25;
    const DBL_US: u32 = 12000;
    const REP_DELAY: u32 = 400000;
    const REP_IVAL: u32 = 100000;
    const NW: u32 = 1024;
    let mut qts = [0u32; 256];
    let mut qtype = [0u32; 256];
    let mut qcode = [0u32; 256];
    let mut wx = [0u32; 1024];
    let mut wy = [0u32; 1024];
    let mut ww = [0u32; 1024];
    let mut wh = [0u32; 1024];
    let mut wflags = [0u32; 1024];
    let mut wparent = [0u32; 1024];
    let mut gstart = [0u32; 161];
    let mut gcur = [0u32; 161];
    let mut gitems = [0u32; 10240];
    let mut hdue = [0u32; 8192];
    let mut hcode = [0u32; 8192];
    let mut hgen = [0u32; 8192];
    let mut gens = [0u32; 256];
    let mut keybits = [0u32; 8];
    let mut cs: u32 = 0;
    let mut x: u32 = 66667;
    for _ in 0..ROUNDS {
        wparent[0] = 0;
        for i in 0..NW as usize {
            if i > 0 {
                wparent[i] = (i as u32 - 1) / 4;
            }
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            wx[i] = (x >> 4) % 1216;
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            wy[i] = (x >> 4) % 736;
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            ww[i] = 16 + (x >> 4) % 112;
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            wh[i] = 16 + (x >> 4) % 80;
            wflags[i] = (x >> 8) & 255;
        }
        for c in 0..161 {
            gstart[c] = 0;
        }
        for i in 0..NW as usize {
            let cx0 = wx[i] / 80;
            let cy0 = wy[i] / 80;
            let mut cx1 = (wx[i] + ww[i] - 1) / 80;
            if cx1 > 15 {
                cx1 = 15;
            }
            let mut cy1 = (wy[i] + wh[i] - 1) / 80;
            if cy1 > 9 {
                cy1 = 9;
            }
            for cy in cy0..=cy1 {
                for cx in cx0..=cx1 {
                    gstart[(cy * 16 + cx + 1) as usize] += 1;
                }
            }
        }
        for c in 0..160 {
            gstart[c + 1] += gstart[c];
        }
        for c in 0..161 {
            gcur[c] = gstart[c];
        }
        for i in 0..NW as usize {
            let cx0 = wx[i] / 80;
            let cy0 = wy[i] / 80;
            let mut cx1 = (wx[i] + ww[i] - 1) / 80;
            if cx1 > 15 {
                cx1 = 15;
            }
            let mut cy1 = (wy[i] + wh[i] - 1) / 80;
            if cy1 > 9 {
                cy1 = 9;
            }
            for cy in cy0..=cy1 {
                for cx in cx0..=cx1 {
                    gitems[gcur[(cy * 16 + cx) as usize] as usize] = i as u32;
                    gcur[(cy * 16 + cx) as usize] += 1;
                }
            }
        }
        for i in 0..8 {
            keybits[i] = 0;
        }
        for i in 0..256 {
            gens[i] = 0;
        }
        let mut hn: u32 = 0;
        let mut head: u32 = 0;
        let mut tail: u32 = 0;
        let mut mods: u32 = 0;
        let mut mx: u32 = 640;
        let mut my: u32 = 400;
        let mut drag: u32 = 0;
        let mut hover: u32 = NW;
        let mut last_click: u32 = 0;
        let mut clicks: u32 = 0;
        let mut dbls: u32 = 0;
        let mut hits: u32 = 0;
        let mut hoverchg: u32 = 0;
        let mut gen: u32 = 0;
        let mut frame: u32 = 0;
        let mut handled: u32 = 0;
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        let mut ev_ts: u32 = 100 + (x >> 7) % 2900;
        let mut ev_tb: u32 = x & 7;
        let mut ev_code: u32 = (x >> 24) & 255;
        loop {
            frame += FRAME_US;
            while gen < EVENTS && ev_ts < frame {
                qts[(tail & 255) as usize] = ev_ts;
                qtype[(tail & 255) as usize] = ev_tb;
                qcode[(tail & 255) as usize] = ev_code;
                tail += 1;
                gen += 1;
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                ev_ts += 100 + (x >> 7) % 2900;
                ev_tb = x & 7;
                ev_code = (x >> 24) & 255;
            }
            if handled < frame {
                handled = frame;
            }
            while hn > 0 && hdue[0] < frame {
                let due = hdue[0];
                let rc = hcode[0];
                let rg = hgen[0];
                hn -= 1;
                hdue[0] = hdue[hn as usize];
                hcode[0] = hcode[hn as usize];
                hgen[0] = hgen[hn as usize];
                let mut si: usize = 0;
                loop {
                    let l = si * 2 + 1;
                    if l >= hn as usize {
                        break;
                    }
                    let mut sm = l;
                    if l + 1 < hn as usize && hdue[l + 1] < hdue[l] {
                        sm = l + 1;
                    }
                    if hdue[si] <= hdue[sm] {
                        break;
                    }
                    hdue.swap(si, sm);
                    hcode.swap(si, sm);
                    hgen.swap(si, sm);
                    si = sm;
                }
                if gens[rc as usize] == rg && ((keybits[(rc >> 5) as usize] >> (rc & 31)) & 1) != 0 {
                    handled += PROC_US;
                    let lat = handled - due;
                    cs = cs.wrapping_mul(1000003).wrapping_add(lat ^ rc);
                    hn = il_push(&mut hdue, &mut hcode, &mut hgen, hn, due + REP_IVAL, rc, rg);
                }
            }
            while head != tail {
                let ts = qts[(head & 255) as usize];
                let tb = qtype[(head & 255) as usize];
                let co = qcode[(head & 255) as usize];
                head += 1;
                handled += PROC_US;
                let lat = handled - ts;
                if tb < 4 {
                    mx = (mx + (co & 15)) % 1280;
                    my = (my + (co >> 4)) % 800;
                    let hit = il_hit(mx, my, &wx, &wy, &ww, &wh, &gstart, &gitems);
                    if hit != hover {
                        hoverchg += 1;
                        hover = hit;
                    }
                    if drag != 0 {
                        hits += 1;
                    }
                    cs = cs.wrapping_mul(1000003).wrapping_add(lat ^ mods);
                    cs = cs.wrapping_mul(1000003).wrapping_add(il_bubble(hit, &wflags, &wparent));
                } else if tb < 6 {
                    keybits[(co >> 5) as usize] |= 1u32 << (co & 31);
                    gens[co as usize] += 1;
                    if co < 8 {
                        mods |= 1 << co;
                    }
                    if co < 32 {
                        hn = il_push(&mut hdue, &mut hcode, &mut hgen, hn, ts + REP_DELAY, co, gens[co as usize]);
                    }
                    cs = cs.wrapping_mul(1000003).wrapping_add(lat ^ mods);
                } else if tb == 6 {
                    keybits[(co >> 5) as usize] &= !(1u32 << (co & 31));
                    gens[co as usize] += 1;
                    if co < 8 {
                        mods &= !(1 << co);
                    }
                    cs = cs.wrapping_mul(1000003).wrapping_add(lat ^ mods);
                } else {
                    if ts - last_click < DBL_US {
                        dbls += 1;
                    } else {
                        clicks += 1;
                    }
                    last_click = ts;
                    drag ^= 1;
                    let hit = il_hit(mx, my, &wx, &wy, &ww, &wh, &gstart, &gitems);
                    if hit != NW {
                        hits += 1;
                    }
                    cs = cs.wrapping_mul(1000003).wrapping_add(lat ^ mods);
                    cs = cs.wrapping_mul(1000003).wrapping_add(il_bubble(hit, &wflags, &wparent));
                }
            }
            if gen >= EVENTS && head == tail {
                break;
            }
        }
        let mut kb: u32 = 0;
        for i in 0..8 {
            kb ^= keybits[i];
        }
        cs = cs.wrapping_mul(1000003).wrapping_add(mx);
        cs = cs.wrapping_mul(1000003).wrapping_add(my);
        cs = cs.wrapping_mul(1000003).wrapping_add(clicks);
        cs = cs.wrapping_mul(1000003).wrapping_add(dbls);
        cs = cs.wrapping_mul(1000003).wrapping_add(hits);
        cs = cs.wrapping_mul(1000003).wrapping_add(hoverchg);
        cs = cs.wrapping_mul(1000003).wrapping_add(hn);
        cs = cs.wrapping_mul(1000003).wrapping_add(kb);
    }
    println!("checksum {}", cs);
}

fn main() {
    bench_inputlat();
}