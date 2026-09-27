/* Simulated input event pipeline — complex benchmark with spatial grid hashing,
   event queue (ring buffer), min-heap timer, widget tree, and 20 rounds of 1M
   events each. Prints checksum so all versions agree. */
#include <stdint.h>
#include <stdio.h>

static uint32_t il_push(uint32_t *hd, uint32_t *hc, uint32_t *hg, uint32_t hn,
                        uint32_t d, uint32_t c, uint32_t g) {
    uint32_t i = hn;
    hd[i] = d; hc[i] = c; hg[i] = g;
    while (i > 0) {
        uint32_t p = (i - 1) / 2;
        if (hd[p] <= hd[i]) break;
        uint32_t td = hd[p]; hd[p] = hd[i]; hd[i] = td;
        uint32_t tc = hc[p]; hc[p] = hc[i]; hc[i] = tc;
        uint32_t tg = hg[p]; hg[p] = hg[i]; hg[i] = tg;
        i = p;
    }
    return hn + 1;
}

static uint32_t il_hit(uint32_t mx, uint32_t my, const uint32_t *wx, const uint32_t *wy,
                       const uint32_t *ww, const uint32_t *wh,
                       const uint32_t *gstart, const uint32_t *gitems) {
    uint32_t c = (my / 80u) * 16u + mx / 80u;
    uint32_t k = gstart[c + 1u];
    while (k > gstart[c]) {
        k -= 1;
        uint32_t i = gitems[k];
        if (mx >= wx[i] && mx < wx[i] + ww[i] && my >= wy[i] && my < wy[i] + wh[i]) return i;
    }
    return 1024;
}

static uint32_t il_bubble(uint32_t hit, const uint32_t *wflags, const uint32_t *wparent) {
    if (hit >= 1024u) return 0;
    uint32_t acc = 0;
    uint32_t node = hit;
    for (;;) {
        acc = acc * 31u + wflags[node];
        if (node == 0) break;
        node = wparent[node];
    }
    return acc;
}

static void bench_inputlat(void) {
    const uint32_t EVENTS = 1000000;
    const int ROUNDS = 20;
    const uint32_t FRAME_US = 4000;
    const uint32_t PROC_US = 25;
    const uint32_t DBL_US = 12000;
    const uint32_t REP_DELAY = 400000;
    const uint32_t REP_IVAL = 100000;
    const uint32_t NW = 1024;
    uint32_t qts[256], qtype[256], qcode[256];
    uint32_t wx[1024], wy[1024], ww[1024], wh[1024], wflags[1024], wparent[1024];
    uint32_t gstart[161], gcur[161];
    uint32_t gitems[10240];
    uint32_t hdue[8192], hcode[8192], hgen[8192];
    uint32_t gens[256];
    uint32_t keybits[8];
    uint32_t cs = 0;
    uint32_t x = 66667;
    for (int round = 0; round < ROUNDS; round++) {
        wparent[0] = 0;
        for (uint32_t i = 0; i < NW; i++) {
            if (i > 0) wparent[i] = (i - 1) / 4;
            x = x * 1664525u + 1013904223u; wx[i] = (x >> 4) % 1216u;
            x = x * 1664525u + 1013904223u; wy[i] = (x >> 4) % 736u;
            x = x * 1664525u + 1013904223u; ww[i] = 16u + (x >> 4) % 112u;
            x = x * 1664525u + 1013904223u; wh[i] = 16u + (x >> 4) % 80u;
            wflags[i] = (x >> 8) & 255u;
        }
        for (uint32_t c = 0; c < 161; c++) gstart[c] = 0;
        for (uint32_t i = 0; i < NW; i++) {
            uint32_t cx0 = wx[i] / 80u, cy0 = wy[i] / 80u;
            uint32_t cx1 = (wx[i] + ww[i] - 1u) / 80u; if (cx1 > 15u) cx1 = 15u;
            uint32_t cy1 = (wy[i] + wh[i] - 1u) / 80u; if (cy1 > 9u) cy1 = 9u;
            for (uint32_t cy = cy0; cy <= cy1; cy++)
                for (uint32_t cx = cx0; cx <= cx1; cx++)
                    gstart[cy * 16u + cx + 1u] += 1;
        }
        for (uint32_t c = 0; c < 160; c++) gstart[c + 1] += gstart[c];
        for (uint32_t c = 0; c < 161; c++) gcur[c] = gstart[c];
        for (uint32_t i = 0; i < NW; i++) {
            uint32_t cx0 = wx[i] / 80u, cy0 = wy[i] / 80u;
            uint32_t cx1 = (wx[i] + ww[i] - 1u) / 80u; if (cx1 > 15u) cx1 = 15u;
            uint32_t cy1 = (wy[i] + wh[i] - 1u) / 80u; if (cy1 > 9u) cy1 = 9u;
            for (uint32_t cy = cy0; cy <= cy1; cy++)
                for (uint32_t cx = cx0; cx <= cx1; cx++) {
                    gitems[gcur[cy * 16u + cx]] = i;
                    gcur[cy * 16u + cx] += 1;
                }
        }
        for (int i = 0; i < 8; i++) keybits[i] = 0;
        for (int i = 0; i < 256; i++) gens[i] = 0;
        uint32_t hn = 0;
        uint32_t head = 0, tail = 0;
        uint32_t mods = 0, mx = 640, my = 400, drag = 0;
        uint32_t hover = NW;
        uint32_t last_click = 0, clicks = 0, dbls = 0, hits = 0, hoverchg = 0;
        uint32_t gen = 0, frame = 0, handled = 0;
        x = x * 1664525u + 1013904223u;
        uint32_t ev_ts = 100u + (x >> 7) % 2900u;
        uint32_t ev_tb = x & 7u;
        uint32_t ev_code = (x >> 24) & 255u;
        for (;;) {
            frame += FRAME_US;
            while (gen < EVENTS && ev_ts < frame) {
                qts[tail & 255u] = ev_ts;
                qtype[tail & 255u] = ev_tb;
                qcode[tail & 255u] = ev_code;
                tail += 1;
                gen += 1;
                x = x * 1664525u + 1013904223u;
                ev_ts += 100u + (x >> 7) % 2900u;
                ev_tb = x & 7u;
                ev_code = (x >> 24) & 255u;
            }
            if (handled < frame) handled = frame;
            while (hn > 0 && hdue[0] < frame) {
                uint32_t due = hdue[0], rc = hcode[0], rg = hgen[0];
                hn -= 1;
                hdue[0] = hdue[hn]; hcode[0] = hcode[hn]; hgen[0] = hgen[hn];
                uint32_t si = 0;
                for (;;) {
                    uint32_t l = si * 2 + 1;
                    if (l >= hn) break;
                    uint32_t sm = l;
                    if (l + 1 < hn && hdue[l + 1] < hdue[l]) sm = l + 1;
                    if (hdue[si] <= hdue[sm]) break;
                    uint32_t td = hdue[si]; hdue[si] = hdue[sm]; hdue[sm] = td;
                    uint32_t tc = hcode[si]; hcode[si] = hcode[sm]; hcode[sm] = tc;
                    uint32_t tg = hgen[si]; hgen[si] = hgen[sm]; hgen[sm] = tg;
                    si = sm;
                }
                if (gens[rc] == rg && ((keybits[rc >> 5] >> (rc & 31u)) & 1u) != 0) {
                    handled += PROC_US;
                    uint32_t lat = handled - due;
                    cs = cs * 1000003u + (lat ^ rc);
                    hn = il_push(hdue, hcode, hgen, hn, due + REP_IVAL, rc, rg);
                }
            }
            while (head != tail) {
                uint32_t ts = qts[head & 255u];
                uint32_t tb = qtype[head & 255u];
                uint32_t co = qcode[head & 255u];
                head += 1;
                handled += PROC_US;
                uint32_t lat = handled - ts;
                if (tb < 4) {
                    mx = (mx + (co & 15u)) % 1280u;
                    my = (my + (co >> 4)) % 800u;
                    uint32_t hit = il_hit(mx, my, wx, wy, ww, wh, gstart, gitems);
                    if (hit != hover) { hoverchg += 1; hover = hit; }
                    if (drag != 0) hits += 1;
                    cs = cs * 1000003u + (lat ^ mods);
                    cs = cs * 1000003u + il_bubble(hit, wflags, wparent);
                } else if (tb < 6) {
                    keybits[co >> 5] |= 1u << (co & 31u);
                    gens[co] += 1;
                    if (co < 8u) mods |= 1u << co;
                    if (co < 32u) hn = il_push(hdue, hcode, hgen, hn, ts + REP_DELAY, co, gens[co]);
                    cs = cs * 1000003u + (lat ^ mods);
                } else if (tb == 6) {
                    keybits[co >> 5] &= ~(1u << (co & 31u));
                    gens[co] += 1;
                    if (co < 8u) mods &= ~(1u << co);
                    cs = cs * 1000003u + (lat ^ mods);
                } else {
                    if (ts - last_click < DBL_US) dbls += 1; else clicks += 1;
                    last_click = ts;
                    drag ^= 1u;
                    uint32_t hit = il_hit(mx, my, wx, wy, ww, wh, gstart, gitems);
                    if (hit != NW) hits += 1;
                    cs = cs * 1000003u + (lat ^ mods);
                    cs = cs * 1000003u + il_bubble(hit, wflags, wparent);
                }
            }
            if (gen >= EVENTS && head == tail) break;
        }
        uint32_t kb = 0;
        for (int i = 0; i < 8; i++) kb ^= keybits[i];
        cs = cs * 1000003u + mx;
        cs = cs * 1000003u + my;
        cs = cs * 1000003u + clicks;
        cs = cs * 1000003u + dbls;
        cs = cs * 1000003u + hits;
        cs = cs * 1000003u + hoverchg;
        cs = cs * 1000003u + hn;
        cs = cs * 1000003u + kb;
    }
    printf("checksum %u\n", cs);
}

int main(void) {
    bench_inputlat();
    return 0;
}