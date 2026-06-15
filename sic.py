#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import tempfile

from sic.preprocess import Preprocess, apply_inc_dirs, apply_defines, apply_default_inc_dirs
from sic.scan import Scan
from sic.parser import Parser
from sic.codegen import Codegen
from sic.optimize import Optimize
import sic.ast


def _run(cmd):
    result = subprocess.run(cmd, stderr=subprocess.PIPE)
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors='replace'))
        sys.exit(result.returncode)


def _ir_to_obj(ir_string, obj_path):
    """Compile an LLVM IR string to a native object file via llvm-as + llc."""
    with tempfile.NamedTemporaryFile(suffix='.ir', mode='w', delete=False) as ir_f:
        ir_f.write(ir_string)
        ir_path = ir_f.name
    bc_path = ir_path + '.bc'
    try:
        _run(['llvm-as', ir_path, '-o', bc_path])
        _run(['llc', '-O0', '-relocation-model=pic', '-filetype=obj', bc_path, '-o', obj_path])
    finally:
        try:
            os.unlink(ir_path)
        except OSError:
            pass
        try:
            os.unlink(bc_path)
        except OSError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="sic")
    parser.add_argument("-o", "--output", dest="output")
    parser.add_argument("-d", "--debug", action='store_true')
    parser.add_argument("-S", action='store_true', dest='emit_ir',
                        help="Output LLVM IR (default: stdout)")
    parser.add_argument("-c", action='store_true', dest='emit_obj',
                        help="Compile to object file, do not link")
    # Legacy flag kept for backward compatibility
    parser.add_argument("--gen", action='store_true',
                        help="Output LLVM IR to stdout (same as -S)")
    parser.add_argument("--ast", action='store_true')
    parser.add_argument("--raw-dict", action='store_true')
    parser.add_argument("--print-pair", action='store_true')
    parser.add_argument("-O", "--opt", action='store')
    parser.add_argument("-D", nargs="*", action="append")
    parser.add_argument("-I", nargs="*", action="append")
    parser.add_argument("filename")

    args = parser.parse_args()

    if args.print_pair:
        sic.ast.set_pair(args.print_pair)

    pre = Preprocess(args.filename, debug=args.debug, cpp="cpp")
    apply_default_inc_dirs(pre)
    apply_inc_dirs(pre, args.I)
    apply_defines(pre, args.D)
    preprocessed = pre.process()

    s = Scan()
    p = Parser(s, debug=args.debug)
    p.define_type("__builtin_va_list")
    r = p.parse(args.filename, preprocessed)

    if args.opt and int(args.opt) > 0:
        sys.stderr.write("Optimizing, level {}\n".format(args.opt))
        r = Optimize(r, args.opt).run()

    sys.setrecursionlimit(6500)

    if args.raw_dict and r:
        import beeprint
        beeprint.pp(r.to_json(), max_depth=6000)

    if args.ast and r:
        print(json.dumps(r.to_json(), indent=2))

    if not p.success():
        sys.exit(1)

    if not r:
        sys.exit(0)

    gen = Codegen(r, args.filename)
    ir_string = gen.generate()

    if not ir_string:
        sys.exit(1)

    emit_ir = args.emit_ir or args.gen

    if emit_ir:
        # -S / --gen: output LLVM IR
        if args.output:
            with open(args.output, 'w') as f:
                f.write(ir_string)
        else:
            print(ir_string)

    elif args.emit_obj:
        # -c: compile to object file only
        if args.output:
            obj_path = args.output
        else:
            base = os.path.splitext(os.path.basename(args.filename))[0]
            obj_path = base + '.o'
        _ir_to_obj(ir_string, obj_path)

    else:
        # Default: compile and link into a binary
        out_path = args.output or 'a.out'
        with tempfile.NamedTemporaryFile(suffix='.o', delete=False) as obj_f:
            obj_path = obj_f.name
        try:
            _ir_to_obj(ir_string, obj_path)
            _run([os.environ.get('CC', 'cc'), obj_path, '-o', out_path, '-lm'])
        finally:
            try:
                os.unlink(obj_path)
            except OSError:
                pass
