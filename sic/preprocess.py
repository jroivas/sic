#!/usr/bin/env python3

import os
import subprocess


class Op:
    def __init__(self, op):
        self.op = op

    def __repr__(self):
        return "{}".format(self.op)


class Num:
    def __init__(self, num):
        self.num = num

    def __repr__(self):
        return "{}".format(self.num)


class Macro:
    def __init__(self, name, params, body):
        self.name = name
        self.params = params
        self.body = body

    def __repr__(self):
        return "{}({}) = {}".format(self.name, self.params, self.body)


class SicPreprocessor:
    def __init__(self, fname, data="", debug=False):
        self.data = data
        if not data:
            with open(fname, "r") as fd:
                self.data = fd.read()
        self.datalen = len(self.data)
        self.processed = ""
        self.idx = 0
        self.defines = {}
        self.ignore = []
        self.include_paths = []
        self.debug = debug
        self.macros = {}

    def add_include_path(self, pth):
        self.include_paths.append(pth)

    def define(self, key, val=True):
        self.defines[key] = val

    def undef(self, key):
        if key in self.defines:
            del self.defines[key]

    def next(self):
        if self.idx >= self.datalen:
            return None
        c = self.data[self.idx]
        self.idx += 1
        return c

    def peek(self):
        if self.idx >= self.datalen:
            return None
        return self.data[self.idx]

    def applyval(self, curstack, val):
        if val:
            curstack.append(val)
            val = ""
        return curstack, val

    def parse_macros(self, data):
        i = 0
        len_data = len(data)
        res = []
        while i < len_data:
            if type(data[i]) == list:
                res.append(self.parse_macros(data[i]))
            elif type(data[i]) == Op:
                res.append(data[i])
            elif type(data[i]) == Num:
                res.append(data[i])
            elif data[i] == "defined":
                if i + 1 >= len_data:
                    raise ValueError(
                        "Invalid preprocessor directive: defined without param"
                    )
                parm = data[i + 1]

                if type(parm) == tuple:
                    parm = list(parm)
                if type(parm) != list:
                    raise ValueError(
                        "Invalid preprocessor directive: defined with invalid param: {}".format(
                            parm
                        )
                    )
                if len(parm) == 1:
                    d = self.defines.get(parm[0], None)
                    if d is None:
                        res.append("False")
                    else:
                        res.append("True")
                    i += 1
                else:
                    raise ValueError("Invalid defined")
            else:
                d = self.defines.get(data[i], "False")
                res.append(d)
                # res.append(data[i])

            i += 1
        return res

    def flatten(self, data):
        res = []
        for i in data:
            if type(i) == list:
                res.append(self.flatten(i))
            elif type(i) == bool:
                res.append(str(i))
            elif type(i) == Op:
                res.append(str(i))
            elif type(i) == Num:
                res.append(str(i))
            else:
                res.append(i)
        if self.debug:
            print("DEBUG: flatten result: ", res)
        return "({})".format(" ".join(res))

    def evaluate(self, cond):
        if self.debug:
            print("DEBUG: evaluate: ", cond)
        if type(cond) != bool and not cond:
            raise ValueError("Nothing to evaluate")
        if type(cond) != str:
            return cond
        i = 0
        len_cond = len(cond)
        stack = []
        curstack = []
        # res = []
        num = ""
        val = ""
        while i < len_cond:
            if cond[i].isdigit():
                num += cond[i]
                i += 1
                continue

            if num:
                curstack.append(Num(num))
                num = ""

            if cond[i] == " ":
                curstack, val = self.applyval(curstack, val)
            elif cond[i] == "(":
                curstack, val = self.applyval(curstack, val)
                stack.append(curstack)
                curstack = []
            elif cond[i] == ")":
                curstack, val = self.applyval(curstack, val)
                if not stack:
                    raise ValueError("Closing ) without opening (")
                prevstack = stack.pop()
                prevstack.append(curstack)
                curstack = prevstack
            elif cond[i] == "!":
                curstack, val = self.applyval(curstack, val)
                curstack.append(Op("not"))
            elif cond[i] == "<":
                curstack, val = self.applyval(curstack, val)
                if i + 1 < len_cond and cond[i + 1] == "=":
                    i += 1
                    curstack.append(Op("<="))
                else:
                    curstack.append(Op("<"))
            elif cond[i] == ">":
                curstack, val = self.applyval(curstack, val)
                if i + 1 < len_cond and cond[i + 1] == "=":
                    i += 1
                    curstack.append(Op(">="))
                else:
                    curstack.append(Op(">"))
            elif cond[i] == "|":
                curstack, val = self.applyval(curstack, val)
                if i + 1 >= len_cond:
                    raise ValueError("Invalid preprocessor directive: |")
                if cond[i + 1] != "|":
                    raise ValueError(
                        "Invalid preprocessor directive: |{}".format(cond[i + 1])
                    )
                curstack.append(Op("or"))
                i += 1
            elif cond[i] == "&":
                curstack, val = self.applyval(curstack, val)
                if i + 1 >= len_cond:
                    raise ValueError("Invalid preprocessor directive: &")
                if cond[i + 1] != "&":
                    raise ValueError(
                        "Invalid preprocessor directive: &{}".format(cond[i + 1])
                    )
                curstack.append(Op("and"))
                i += 1
            else:
                val += cond[i]

            i += 1

        if num:
            curstack.append(Num(num))
        curstack, val = self.applyval(curstack, val)

        if self.debug:
            print("DEBUG: evaluate before macros: ", curstack)
        curstack = self.parse_macros(curstack)
        curstack = self.flatten(curstack)

        if self.debug:
            print("DEBUG: evaluate after macros and flatten: ", curstack)
        return eval(curstack)

    def getdefine(self, key):
        return self.defines.get(key, False)

    def do_include(self, fname):
        if self.debug:
            print("++ Include: {}".format(fname))
        # Include the file in place
        databak = self.data
        with open(fname, "r") as fd:
            newdata = fd.read()
        self.data = databak[: self.idx] + newdata + databak[self.idx :]
        self.datalen = len(self.data)

    def include_file(self, incfile, local):
        if local:
            tmp = os.path.join(".", incfile)
            if os.path.exists(tmp):
                self.do_include(tmp)
                return True

        for pth in self.include_paths:
            tmp = os.path.join(pth, incfile)
            if os.path.exists(tmp):
                self.do_include(tmp)
                return True

        return False

    def include(self, inclist):
        local = False

        # We can have "" or <>
        if not inclist or len(inclist) != 1:
            raise ValueError("Missing/invalid include: {}".format(inc))

        inc = inclist[0].strip()
        if not inc or len(inc) <= 2:
            raise ValueError("Missing include: {}".format(inc))

        if inc[0] == "<":
            if inc[-1] != ">":
                raise ValueError("Invalid include: {}".format(inc))
        elif inc[0] == '"':
            if inc[-1] != '"':
                raise ValueError("Invalid include: {}".format(inc))
            local = True
        else:
            raise ValueError("Invalid include: {}".format(inc))

        inc = inc[1:-1]
        if not self.include_file(inc, local):
            raise ValueError("Can't find include {}".format(inc))

    def handle_define(self, define):
        key = ""
        params = ""
        stack = []
        tmp = ""
        is_macro = False
        for k in define:
            # print(stack, key, params, tmp, k)
            if not stack and k == " ":
                break
            if k == "(":
                is_macro = True
                if not key and tmp:
                    key = tmp
                    tmp = ""
                stack.append(k)
            elif k == ")":
                if not stack:
                    raise ValueError("Unbalanced ) in macro")
                stack.pop()
                if not stack:
                    params = tmp
                    tmp = ""
            else:
                tmp += k
        if is_macro:
            if tmp:
                raise ValueError("ERR tmp", tmp)
            rpos = len(key) + len(params) + 2
            body = define[rpos + 1 :]
            self.macros[key.lower()] = Macro(key, params, body)
            # print("KEY : |{}|".format(key))
            # print("PARM: |{}|".format(params))
            # print("BODY: |{}|".format(body))
        else:
            key = tmp
            rpos = len(key)
            body = define[rpos + 1 :]
            # print("KEY : |{}|".format(key))
            # print("BODY: |{}|".format(body))
            if body:
                self.define(tmp, body)
            else:
                self.define(tmp)

    def handle_directive(self, directive):
        directive = directive.strip()
        parts = [x.strip() for x in directive.split()]
        if not parts:
            raise ValueError("Invalid preprocessor directive")

        if parts[0].lower() == "if":
            cond = self.evaluate(" ".join(parts[1:]))
            self.ignore.append(not cond)
        elif parts[0].lower() == "ifdef":
            cond = self.evaluate(self.getdefine(parts[1]))
            self.ignore.append(not cond)
        elif parts[0].lower() == "undef":
            if len(parts[1:]) != 1:
                raise ValueError("Invalid undef: {}".format(directive))
            self.undef(parts[1])
            # print("UNDEF", parts[1])
            # cond = self.evaluate(" ".join(parts[1:]))
        elif parts[0].lower() == "ifndef":
            cond = self.evaluate(self.getdefine(parts[1]))
            self.ignore.append(cond)
        elif parts[0].lower() == "else":
            cond = self.ignore.pop()
            self.ignore.append(not cond)
        elif parts[0].lower() == "endif":
            self.ignore.pop()
        elif parts[0].lower() == "define":
            if not self.ignore:
                self.handle_define(" ".join(parts[1:]))
        elif parts[0].lower() == "include":
            if not self.ignore:
                self.include(parts[1:])
        else:
            raise ValueError("Unknown directive {}".format(parts[0]))

    def isignore(self):
        for i in self.ignore:
            if i:
                return True
        return False

    def process(self):
        linestart = True
        while True:
            c = self.next()
            if c is None:
                break
            if c == " " or c == "\t":
                self.processed += c
                continue
            if linestart and c == "#":
                directive = ""
                c = self.next()
                slash = False
                in_comment = False
                while c != "\n":
                    if c == "/":
                        c2 = self.peek()
                        if c2 == "*":
                            c = self.next()
                            c2 = self.peek()
                            while c != "*" or c2 != "/":
                                c = self.next()
                                c2 = self.peek()
                                if c is None or c2 is None:
                                    break
                            if c == "*" and c2 == "/":
                                c = self.next()
                            c = self.next()
                            if c == "\n":
                                break
                        elif c2 == "/":
                            c = self.next()
                            while c != "\n":
                                c = self.next()
                                if c is None:
                                    break
                            break
                    directive += c
                    if c == "\\":
                        slash = True
                    else:
                        slash = False
                    c = self.next()
                    if slash and c == "\n":
                        directive = directive[:-1]
                        c = self.next()
                        slash = False
                if self.debug:
                    print("DIRECTIVE: {}".format(directive))
                self.handle_directive(directive)
                self.processed += c
                continue

            if self.isignore():
                continue

            linestart = False
            if c == "/":
                c2 = self.peek()
                if c2 == "*":
                    # Multiline comment like /* */
                    c = self.next()
                    c2 = self.peek()
                    while c != "*" or c2 != "/":
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
            if c == "\n":
                linestart = True

        return self.processed

    def get(self):
        return self.processed


class WrapPreprocessor:
    def __init__(self, cpp, fname, data="", debug=False):
        self.cpp = cpp
        self.include_paths = []
        self.defines = {}
        self.fname = fname
        self.data = ""

    def add_include_path(self, pth):
        self.include_paths.append(pth)

    def define(self, key, val=True):
        self.defines[key] = val

    def process(self):
        if self.fname:
            #"{cpp} -std=c99 -D__extension__= -D__restrict= {fname}"
            cmd = [
                self.cpp,
                "-std=c99",
                "-D__extension__=",
                "-D__restrict=",
                # FIXME Attributes not supported
                "-D__attribute__(x)=",
                # FIXME Function name export
                "-D__asm__(x)=",
            ]
            for d in self.defines:
                v = self.defines[d]
                if v is None:
                    cmd.append("-D{}".format(d))
                else:
                    cmd.append("-D{}={}".format(d, v))
            cmd.append(self.fname)
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            out, err = process.communicate()
            return out.decode("utf-8")
        else:
            raise ValueError("fff")


class Preprocess:
    def __init__(self, fname, data="", debug=False, cpp=None):
        self.fname = fname
        if cpp:
            self.wrap = WrapPreprocessor(cpp, fname, data, debug)
        else:
            self.wrap = SicPreprocessor(fname, data, debug)

    def add_include_path(self, pth):
        return self.wrap.add_include_path(pth)

    def define(self, key, val=True):
        return self.wrap.define(key, val)

    def process(self):
        return self.wrap.process()


def apply_inc_dirs(pre, incdirs):
    if incdirs is None:
        return

    for i in incdirs:
        i = i.strip()
        pre.add_include_path(i)


def apply_defines(pre, defines):
    if defines is None:
        return

    for d in defines:
        d = d.strip()
        if "=" in d:
            spl = d.split("=", 2)
            pre.define(*spl)
        else:
            pre.define(d)


def apply_default_inc_dirs(pre):
    incdef = [
        "/usr/lib/gcc/x86_64-linux-gnu/13/include",
        "/usr/local/include",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include",
    ]
    apply_inc_dirs(pre, incdef)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="sicpp")
    parser.add_argument("-D", nargs="*", action="append")
    parser.add_argument("-I", nargs="*", action="append")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--cpp")
    parser.add_argument("filename")

    args = parser.parse_args()

    pre = Preprocess(args.filename, debug=args.debug, cpp=args.cpp)
    apply_default_inc_dirs(pre)
    apply_inc_dirs(pre, args.I)
    apply_defines(pre, args.D)
    res = pre.process()
    print(res)
