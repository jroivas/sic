#!/usr/bin/env python3

import argparse
import sys
import json

from sic.preprocess import Preprocess, apply_inc_dirs, apply_defines, apply_default_inc_dirs
from sic.scan import Scan
from sic.parser import Parser
import sic.ast


def scan(fname):
    s = Scan(fname)

    while True:
        t = s.scan()
        if t is None:
            break
        #if t.tokentype == TokenType.INVALID:
        #    print("*** ERROR INVALID")
        print(t)

def parse(fname):
    s = Scan()
    p = Parser(s)
    return p.parse(fname)


if __name__ == "__main__":
    """
    test_lang = {
        "expression": [
            ("expression", TokenType.PLUS, "term"),
            ("expression", TokenType.MINUS, "term"),
            ("term",),
        ],
        "term": [
            ("term", TokenType.STAR, "factor"),
            ("term", TokenType.SLASH, "factor"),
            ("factor",),
        ],
        "factor": [
            (TokenType.INT_LIT,),
            (TokenType.ROUND_OPEN, "expression", TokenType.ROUND_CLOSE),
        ],
    }
    """

    parser = argparse.ArgumentParser(prog="sic")
    parser.add_argument("-o", "--output")
    parser.add_argument("-d", "--debug", action='store_true')
    parser.add_argument("--ast", action='store_true')
    parser.add_argument("--raw-dict", action='store_true')
    parser.add_argument("--print-pair", action='store_true')
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

    #print("PRE", preprocessed)
    s = Scan()
    p = Parser(s, debug=args.debug)
    p.define_type("__builtin_va_list")
    r = p.parse(args.filename, preprocessed)
    #r = parse()
    #print(r)
    #print(r.to_json())
    sys.setrecursionlimit(6500)
    if args.raw_dict and r:
        import beeprint
        #pprint.pprint(r.to_json())
        beeprint.pp(r.to_json(), max_depth=6000)
        #print(r.to_json())
    if args.ast and r:
        print(json.dumps(r.to_json(), indent=2))
    if not p.success():
        sys.exit(1)
