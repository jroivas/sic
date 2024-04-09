#!/usr/bin/env python3

import argparse
import sys

from sic.token import TokenType
from sic.scan import Scan


def scan(fname):
    s = Scan(fname)

    while True:
        t = s.scan()
        if t is None:
            break
        if t.tokentype == TokenType.INVALID:
            print("*** ERROR INVALID")
        print(t)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="sic")
    parser.add_argument("-o", "--output")
    parser.add_argument("filename")

    args = parser.parse_args()
    scan(args.filename)
