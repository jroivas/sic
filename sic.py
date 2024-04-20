#!/usr/bin/env python3

import argparse
import sys
import json

from sic.preprocess import Preprocess
from sic.scan import Scan
from sic.parser import Parser


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
    parser.add_argument("filename")

    args = parser.parse_args()

    """
    scan(args.filename)
    """
    pre = Preprocess(args.filename)
    preprocessed = pre.process()
    #print("PRE", preprocessed)
    s = Scan()
    p = Parser(s, debug=args.debug)
    r = p.parse(args.filename, preprocessed)
    #r = parse()
    print(r)
    print(r.to_json())
    print(json.dumps(r.to_json(), indent=2))
    if not p.success():
        sys.exit(1)
