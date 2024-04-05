#!/usr/bin/env python

import sys
from enum import Enum

class TokenType(Enum):
    INVALID = 0
    PLUS = 1
    PLUSPLUS = 2
    INT_LIT = 3
    MINUS = 4
    MINUSMINUS = 5

class EOFError(Exception):
    pass

class Token:
    def __init__(self, line, col, tokentype=TokenType.INVALID):
        self.line = line
        self.col = col
        self.tokentype = tokentype
        self.value = ''

    def set(self, value, tokentype):
        self.value = value
        self.tokentype = tokentype

    def __repr__(self):
        return 'Token({}, {})'.format(self.tokentype, self.value)

class Scan:
    numbers = "0123456789abcdef"

    def __init__(self, filename):
        self.fname = filename
        self.data = r''
        with open(self.fname, 'rb') as fd:
            self.data = fd.read()
        self.data_len = len(self.data)
        self.buffer = []
        self.idx = 0
        self.line = 0
        self.col = 0

    def next(self):
        """
        Take next character
        """
        if self.idx >= self.data_len:
            raise EOFError
        c = self.data[self.idx]
        if c == '\n':
            self.line += 1
            self.col = 0
        self.idx += 1
        return chr(c)

    def skip(self):
        """
        Take next markable character
        """
        c = self.next()
        while c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\f':
            c = self.next()
        return c

    def undo(self):
        if self.idx == 0:
            raise ValueError("Invalid undo")
        self.idx -= 1
        if self.idx == '\n':
            self.line -= 1
        elif self.col:
            self.col -= 1

    def scan_number(self, c):
        radix = 10
        tmp = ''

        if c == '0':
            tmp += c
            c = self.next()
            if c == 'x':
                tmp += c
                radix = 16
                c = self.next()
            else:
                radix = 8

        while c.lower() in self.numbers:
            tmp += c
            c = self.next()
        self.undo()

        return int(tmp, radix)

    def scan(self):
        try:
            c = self.skip()
        except EOFError:
            return None

        token = Token(self.line, self.col)
        ttype = TokenType.INVALID

        if c == '+':
            ttype = TokenType.PLUS
            c2 = self.next()
            if c2 =='+':
                ttype = TokenType.PLUSPLUS
                c += c2
            else:
                self.undo()
        elif c == '-':
            ttype = TokenType.MINUS
            c2 = self.next()
            if c2 =='-':
                ttype = TokenType.MINUSMINUS
                c += c2
            else:
                self.undo()
        else:
            if c.isdigit():
                ttype = TokenType.INT_LIT
                c = self.scan_number(c)

        token.set(c, ttype)
        return token


if __name__ == '__main__':
    s = Scan(sys.argv[1])
    while True:
        t = s.scan()
        if t is None:
            break
        print(t)
