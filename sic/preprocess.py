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
        self.ignore = []

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

    def evaluate(self, cond):
        res = []
        for c in cond:
            # TODO macros
            d = self.defines.get(c, None)
            if d is None:
                d = c
            if type(d) == bool:
                res.append(d)
            elif d.isdigit():
                res.append(bool(int(d)))
            elif type(d) == int:
                res.append(bool(d))
            elif d == "(" or d == ")":
                res.append(d)
            elif d == "!":
                res.append("not")
            elif d == "||":
                res.append("or")
            elif d == "||":
                res.append("and")
            elif type(d) == str:
                # Not found so evaluate to false
                rr = self.eval_macro(d)
                if type(rr) == bool:
                    res.append(rr)
                else:
                    res.append(False)
            else:
                raise ValueError("Unknown type {} for {}".format(type(d), d))
        # Now we should have booleans, conditions and braces, join and eval
        estr = " ".join([str(x) for x in res])
        res = eval(estr)
        return res

    def eval_macro(self, macrodef):
        if '(' not in macrodef:
            return macrodef
        if ')' not in macrodef:
            raise ValueError("Macro missing closing ')'")

        parts = macrodef.split('(', 2)
        macro = parts[0].strip().lower()
        if macro == 'defined':
            rpart = parts[1].rindex(')')
            if parts[1][rpart:] != ')':
                raise ValueError("Invalid def")
            return self.evaluate([parts[1][:rpart]])

        raise ValueError("Invalid macro: {}".format(macro))

    def getdefine(self, key):
        return self.defines.get(key, False)

    def handle_directive(self, directive):
        directive = directive.strip()
        parts = [x.strip() for x in directive.split()]
        if not parts:
            raise ValueError("Invalid preprocessor directive")

        if parts[0].lower() == "if":
            cond = self.evaluate(parts[1:])
            self.ignore.append(not cond)
        elif parts[0].lower() == "ifdef":
            # FIXME: Overflow cond
            cond = self.evaluate([self.getdefine(parts[1])])
            self.ignore.append(not cond)
        elif parts[0].lower() == "else":
            cond = self.ignore.pop()
            self.ignore.append(not cond)
        elif parts[0].lower() == "endif":
            self.ignore.pop()
        elif parts[0].lower() == "define":
            self.define(*parts[1:])
        else:
            raise ValueError("Unknown directive {}".format(parts[0]))


    def process(self):
        linestart = True
        while True:
            c = self.next()
            if c is None:
                break
            if c == ' ' or c == '\t':
                self.processed += c
                continue
            if linestart and c == "#":
                directive = ""
                c = self.next()
                while c != '\n':
                    directive += c
                    c = self.next()
                self.handle_directive(directive)
                self.processed += c
                continue

            if self.ignore and self.ignore[-1]:
                continue

            linestart = False
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
            if c == '\n':
                linestart = True

        return self.processed

    def get(self):
        return self.processed


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
    res = pre.process()
    print(res)
