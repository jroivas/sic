#!/usr/bin/env python3

class Preprocess:
    def __init__(self, fname, data=""):
        self.data = data
        if not data:
            with open(fname, "r") as fd:
                self.data = fd.read()
        self.processed = ""
        self.idx = 0
        self.defines = {}

    def define(self, key, val=True):
        self.defines[key] = val

    def undef(self, key):
        del self.defines[key]

    def next(self):
        if self.idx >= len(self.data):
            return None
        c = self.data[self.idx]
        self.idx += 1
        return c

    def peek(self):
        if self.idx >= len(self.data):
            return None
        return self.data[self.idx]

    def process(self):
        while True:
            c = self.next()
            if c is None:
                break
            if c == "/":
                c2 = self.peek()
                if c2 == "*":
                    # Multiline comment like /* */
                    c = self.next()
                    c2 = self.peek()
                    while c != '*' or c2 != "/":
                        c = self.next()
                        c2 = self.peek()
                        if c is None or c2 is None:
                            break
                    if c == "*" and c2 == "/":
                        c = self.next()
                elif c2 == "/":
                    c = self.next()
                    while c != "\n":
                        c = self.next()
                        if c is None:
                            break
                    if c is not None:
                        self.processed += c
                else:
                    self.processed += c
            else:
                self.processed += c

def apply_defines(pre, defines):
    if defines is None:
        return

    for d in defines:
        d = d.strip()
        if '=' in d:
            spl = d.split("=", 2)
            pre.define(*spl)
        else:
            pre.define(d)

if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="sicpp")
    parser.add_argument("-D", nargs="*", action="append")
    parser.add_argument("filename")

    args = parser.parse_args()

    pre = Preprocess(args.filename)
    apply_defines(pre, args.D)
    pre.process()
