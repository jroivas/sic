#!/usr/bin/env python3

import argparse
import sys
import json

from sic.token import TokenType
from sic.scan import Scan
from sic.parser import Parser, Grammar


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
    """
    test_lang = [
        ("expression", [
            ("expression", TokenType.PLUS, "term"),
            ("expression", TokenType.MINUS, "term"),
            ("term",),
        ]),
        ("term", [
            ("term", TokenType.STAR, "factor"),
            ("term", TokenType.SLASH, "factor"),
            ("factor",),
        ]),
        ("factor", [
            (TokenType.INT_LIT,),
            (TokenType.ROUND_OPEN, "expression", TokenType.ROUND_CLOSE),
        ]),
    ]
    g = Grammar(test_lang)
    print(g)
    g.printcases()
    """
    #p = Parser(Scan("", b"3 + 5 * ( 10 - 20 )"), test_lang)
    #p.parse()
    parser = argparse.ArgumentParser(prog="sic")
    parser.add_argument("-o", "--output")
    parser.add_argument("-d", "--debug", action='store_true')
    parser.add_argument("filename")

    args = parser.parse_args()

    """
    scan(args.filename)
    """
    s = Scan()
    p = Parser(s, debug=args.debug)
    r = p.parse(args.filename)
    #r = parse()
    print(r)
    print(r.to_json())
    print(json.dumps(r.to_json(), indent=2))
    if not p.success():
        sys.exit(1)
