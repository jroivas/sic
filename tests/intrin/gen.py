#!/usr/bin/env python3
"""Differential test generator for x86 intrinsics: parses GCC's intrinsic
headers and writes a C file that calls every intrinsic with varied inputs and
prints each result's bytes. Build it with gcc and with sic and diff the output.

usage: gen.py OUT.c HEADER... [--skip name,name] [--only regex] [--drop FILE]
       [--hash print|0xEXPECTED]   (fold results into an FNV hash; see test_0616)
Driven by mk.sh.
"""
import re, sys, random

GCC_INC = '/usr/lib/gcc/x86_64-linux-gnu/15/include/'

args = sys.argv[1:]
out = args.pop(0)
skip = set()
only = None
drop_file = None
hash_mode = None
headers = []
while args:
    a = args.pop(0)
    if a == '--skip': skip |= set(args.pop(0).split(','))
    elif a == '--only': only = re.compile(args.pop(0))
    elif a == '--drop': drop_file = args.pop(0)
    elif a == '--hash': hash_mode = args.pop(0)
    else: headers.append(a)

VEC = {'__m128': 16, '__m128d': 16, '__m128i': 16, '__m64': 8, '__m256': 32, '__m256d': 32, '__m256i': 32,
       '__m128h': 16, '__m256h': 32}
SCALAR = {'int', 'unsigned int', 'long long', 'unsigned long long', 'short', 'char', 'float', 'double',
          'unsigned short', 'unsigned char', 'long', 'unsigned long', 'long long int', '__int64'}
# Intrinsics with effects outside their result, or that are not testable this way.
DEFAULT_SKIP = {'_mm_setcsr', '_mm_getcsr', '_mm_sfence', '_mm_mfence', '_mm_lfence', '_mm_pause', '_mm_prefetch',
                '_mm_clflush', '_mm_malloc', '_mm_free', '_mm_empty', '_m_empty', '_mm_undefined_ps',
                '_mm_undefined_pd', '_mm_undefined_si128', '_mm256_undefined_ps', '_mm256_undefined_pd',
                '_mm256_undefined_si256', '_mm256_zeroall', '_mm256_zeroupper', '_mm_maskmove_si64',
                '_m_maskmovq', '_mm_maskmoveu_si128'}
# Approximations: results are only bounded by the ISA, not bit-defined.
APPROX = {'_mm_rcp_ps', '_mm_rcp_ss', '_mm_rsqrt_ps', '_mm_rsqrt_ss', '_mm256_rcp_ps', '_mm256_rsqrt_ps'}

protos = []
for h in headers:
    src = open(GCC_INC + h).read()
    for m in re.finditer(r'extern __inline\s+([\w\s\*]+?)\s*__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)\s*(_mm\w+|_m_\w+)\s*\(([^)]*)\)', src):
        ret, name, params = m.group(1).strip(), m.group(2), m.group(3).strip()
        if name in skip or name in DEFAULT_SKIP: continue
        if only and not only.search(name): continue
        plist = [] if params in ('', 'void') else [p.strip() for p in params.split(',')]
        ps = []
        ok = True
        for p in plist:
            pm = re.match(r'(.*?)(\w+)$', p)
            ty = pm.group(1).strip()
            const_imm = ty.startswith('const int') or ty.startswith('const unsigned') or (ty == 'const int')
            ty = re.sub(r'\b__restrict\b|\bconst\b', '', ty).strip()
            ty = re.sub(r'\s+', ' ', ty)
            ps.append((ty, const_imm))
        protos.append((name, ret, ps))

seen = set()
uniq = []
for p in protos:
    if p[0] in seen: continue
    seen.add(p[0]); uniq.append(p)
protos = uniq

rng = random.Random(1234)
import os
dropped = set()
if drop_file and os.path.exists(drop_file):
    dropped = set(l.strip() for l in open(drop_file) if l.strip())
linemap = {}

def fbits(f):
    import struct
    return struct.pack('<f', f)

def dbits(f):
    import struct
    return struct.pack('<d', f)

def vec_inputs(n):
    """Byte patterns for an n-byte vector: random, edge integers, special floats."""
    import struct
    out = []
    for _ in range(3):
        out.append(bytes(rng.randrange(256) for _ in range(n)))
    edges = [0x00, 0x01, 0x7f, 0x80, 0xff, 0xfe, 0x81, 0x40]
    out.append(bytes(edges[i % 8] for i in range(n)))
    w = [0x7fff, 0x8000, 0xffff, 0x0001, 0x8001, 0x0000, 0x7ffe, 0x4000]
    out.append(b''.join(struct.pack('<H', w[i % 8]) for i in range(n // 2)))
    fl = [1.5, -2.25, float('nan'), float('inf'), -0.0, 3.0e9, -3.0e9, 1e-40, 0.5, 2.5, -1.5, 65504.0, 1e20, -7.75, 0.1, 123456.7]
    out.append(b''.join(fbits(fl[i % 16]) for i in range(n // 4)))
    dl = [1.5, float('nan'), -0.0, 3.0e9, -1e300, 2.5, -2.5, 5e-324]
    out.append(b''.join(dbits(dl[i % 8]) for i in range(n // 8)))
    fl2 = [0.5, 0.5, -1.0, 2.0, float('-inf'), 1.0, -0.0, float('nan'), 7.0, -3.5, 1e-45, 4.0, 2.0, 2.0, 1.0, 0.0]
    out.append(b''.join(fbits(fl2[i % 16]) for i in range(n // 4)))
    return out

SCALAR_VALS = {
    'int': ['0', '1', '-1', '7', '-128', '2147483647', '(-2147483647-1)', '33', '65535'],
    'unsigned int': ['0u', '1u', '0xffffffffu', '31u', '0x80000000u'],
    'long long': ['0LL', '-1LL', '0x123456789abcdefLL', '(-9223372036854775807LL-1)', '64LL'],
    'unsigned long long': ['0ULL', '0xffffffffffffffffULL', '0x8000000000000000ULL', '15ULL'],
    'short': ['0', '-1', '32767', '(-32768)', '1234'],
    'unsigned short': ['0', '65535', '1234'],
    'char': ['0', '-1', '127', '(-128)', '65'],
    'unsigned char': ['0', '255', '65'],
    'float': ['0.0f', '1.5f', '-2.75f', '3.0e9f', '__builtin_nanf("")', '__builtin_inff()', '-0.0f'],
    'double': ['0.0', '1.5', '-2.75', '3.0e9', '__builtin_nan("")', '-__builtin_inf()', '1e-310'],
    'long': ['0L', '-1L', '0x123456789abcdefL'], 'unsigned long': ['0UL', '0xffffffffffffffffUL'],
    'long long int': ['0LL', '-1LL', '0x123456789abcdefLL'], '__int64': ['0LL', '-1LL', '0x123456789abcdefLL'],
}
IMMS = ['0', '1', '2', '3', '5', '8', '15', '16', '17', '27', '31', '32', '33', '63', '64', '77', '0x4e', '0xb1', '0xe4', '0xff']

lines = []
w = lines.append
w('#include <immintrin.h>')
w('#include <stdio.h>')
w('#include <string.h>')
if hash_mode is None:
    w('static void pb(const char *n, int k, const void *p, int len) { const unsigned char *b = p; printf("%s#%d:", n, k); for (int i = 0; i < len; i++) printf("%02x", b[i]); printf("\\n"); }')
else:
    w('static unsigned long long h_ = 1469598103934665603ULL;')
    w('static void pb(const char *n, int k, const void *p, int len) { const unsigned char *b = p; (void)n; (void)k; for (int i = 0; i < len; i++) { h_ ^= b[i]; h_ *= 1099511628211ULL; } }')
w('static unsigned char buf_in[64] __attribute__((aligned(64)));')
w('static unsigned char buf_out[64] __attribute__((aligned(64)));')
w('static unsigned char pat[64];')

# Input vectors as globals (so the compiler can't fold through them).
inputs = {}
for n in (8, 16, 32):
    vals = vec_inputs(n)
    inputs[n] = len(vals)
    for k, b in enumerate(vals):
        w('static unsigned char in%d_%d[%d] __attribute__((aligned(32))) = {%s};' % (n, k, n, ','.join(str(x) for x in b)))

def vec_expr(ty, k):
    n = VEC[ty]
    return '({ %s v_; memcpy(&v_, in%d_%d, %d); v_; })' % (ty, n, k % inputs[n], n)

# A gather's index vector: lanes 0..3 (int32 or int64), so base + index*scale
# (scale <= 8, elements <= 8 bytes) stays inside buf_in. Random indices made
# both the GCC and the sic binary fault.
w('static const int idx32[8] __attribute__((aligned(32))) = {0, 3, 1, 2, 2, 0, 3, 1};')
w('static const long long idx64[4] __attribute__((aligned(32))) = {2, 0, 3, 1};')
def idx_expr(ty, wide):
    return '({ %s v_; memcpy(&v_, %s, %d); v_; })' % (ty, 'idx64' if wide else 'idx32', VEC[ty])

funcs = []
for name, ret, ps in protos:
    tys = [t for t, _ in ps]
    if any(t not in VEC and t not in SCALAR and not t.endswith('*') for t in tys): continue
    if ret not in VEC and ret not in SCALAR and ret != 'void': continue
    if ret == 'void' and not any(t.endswith('*') for t in tys): continue
    # Argument value lists per position.
    choices = []
    for t, imm in ps:
        if t.endswith('*'): choices.append(['PTR'])
        elif t in VEC: choices.append(['V%d' % k for k in range(inputs[VEC[t]])])
        elif imm: choices.append(IMMS)
        else: choices.append(SCALAR_VALS.get(t, ['0']))
    # Combinations: walk each position's values with the others varied, capped.
    combos = []
    maxlen = max([len(c) for c in choices] + [1])
    for i in range(maxlen):
        combos.append([c[(i * (j + 1) + j) % len(c)] for j, c in enumerate(choices)])
    if len(ps) >= 2:
        for i in range(maxlen):
            combos.append([c[(i + 3 * j) % len(c)] for j, c in enumerate(choices)])
    if any(imm for _, imm in ps):
        # Every immediate with the vector inputs fixed.
        ii = [j for j, (_, imm) in enumerate(ps) if imm][0]
        for v in IMMS:
            c = [ch[1 % len(ch)] for ch in choices]
            c[ii] = v
            combos.append(c)
    body = []
    for k, c in enumerate(combos):
        if '%s#%d' % (name, k) in dropped: continue
        argv = []
        pre = []
        for j, ((t, imm), v) in enumerate(zip(ps, c)):
            if 'gather' in name and v.startswith('V') and j > 0 and ps[j - 1][0].endswith('*'):
                argv.append(idx_expr(t, 'i64gather' in name))
                continue
            if v == 'PTR':
                pre.append('memcpy(buf_in, pat, 64); memcpy(buf_out, pat, 64);')
                argv.append('(%s)(%s)' % (t, 'buf_out' if 'const' not in t and ret == 'void' else 'buf_in'))
            elif v.startswith('V'): argv.append(vec_expr(t, int(v[1:]) + j))
            else: argv.append(v)
        call = '%s(%s)' % (name, ', '.join(argv))
        body.append('    { %s' % ' '.join(pre))
        body.append(('MAP', '%s#%d' % (name, k)))
        if ret == 'void':
            body.append('      %s; pb("%s", %d, buf_out, 64); }' % (call, name, k))
        elif ret in VEC:
            body.append('      %s r_ = %s; %s }' % (ret, call, '' if name in APPROX else 'pb("%s", %d, &r_, sizeof r_);' % (name, k)))
        else:
            body.append('      %s r_ = %s; pb("%s", %d, &r_, sizeof r_); }' % (ret, call, name, k))
    fn = 't_' + name
    funcs.append(fn)
    w('static void %s(void) {' % fn)
    for b in body:
        if isinstance(b, tuple): linemap[len(lines) + 1] = b[1]
        else: lines.append(b)
    w('}')

w('int main(void) {')
w('  for (int i = 0; i < 64; i++) pat[i] = (unsigned char)(i * 37 + 11);')
for fn in funcs: w('  %s();' % fn)
if hash_mode is None:
    w('  return 0;')
elif hash_mode == 'print':
    w('  printf("%llx\\n", h_);')
    w('  return 0;')
else:
    w('  return h_ == %sULL ? 42 : 1;' % hash_mode)
w('}')
open(out, 'w').write('\n'.join(lines) + '\n')
open(out + '.map', 'w').write('\n'.join('%d %s' % kv for kv in sorted(linemap.items())))
print('%d intrinsics' % len(funcs), file=sys.stderr)
