#!/usr/bin/env python3

import sys
from enum import Enum

class EOFError(Exception):
    pass

class SyntaxError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)

class TokenType(Enum):
    INVALID = 0
    PLUS = 1
    PLUSPLUS = 2
    UNDEFINED = 3
    MINUS = 4
    MINUSMINUS = 5
    SEMI = 6
    INT_LIT = 7
    DEC_LIT = 8
    DOT = 9
    IDENTIFIER = 10

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
        self.idx = 0
        self.line = 0
        self.col = 0
        self.tokens = []

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

    def is_space(self, c):
        if c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\f':
            return True
        return False

    def skip(self):
        """
        Take next markable character
        """
        c = self.next()
        while self.is_space(c):
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

    def scan_fraction(self, c):
        tmp = '0'
        div = 1

        while c.lower() in self.numbers:
            tmp += c
            c = self.next()
            div *= 10
        self.undo()

        return [int(tmp), div]

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

    def scan_identifier(self, c):
        tmp = ''

        while c.isalpha() or c.isdigit() or c == '_':
            tmp += c
            c = self.next()
        c.undo()
        return tmp

    def emit(self, token, tokentype, value):
        token.set(value, tokentype)
        self.tokens.append(token)

    def get_token(self):
        if not self.tokens:
            return None
        return self.tokens.pop(0)

    def scan(self):
        if self.tokens:
            return self.get_token()

        try:
            c = self.skip()
        except EOFError:
            return None

        token = Token(self.line, self.col)
        ttype = TokenType.INVALID
        val = c

        if c == '+':
            c2 = self.next()
            if c2 =='+':
                self.emit(token, TokenType.PLUSPLUS, c + c2)
            else:
                self.undo()
                self.emit(token, TokenType.PLUS, c)
        elif c == '-':
            c2 = self.next()
            if c2 =='-':
                self.emit(token, TokenType.MINUSMINUS, c + c2)
            else:
                self.undo()
                self.emit(token, TokenType.MINUS, c)
        elif c == ';':
            self.emit(token, TokenType.SEMI, c)
        else:
            if c.isdigit():
                ttype = TokenType.INT_LIT
                val = self.scan_number(c)
                c = self.next()
            if c == '.':
                c = self.next()
                if c == '.':
                    c = self.next()
                    if c == '.':
                        if ttype != TokenType.INVALID:
                            self.emit(token, ttype, val)
                        self.emit(token, TokenType.ELLIPSIS, "...")
                    else:
                        raise SyntaxError("Got two dots, invalid syntax")
                elif c.isdigit() or self.is_space(c):
                    frac = self.scan_fraction(c)
                    if val == '.':
                        val = 0
                    self.emit(token, TokenType.DEC_LIT, [val, frac])
                else:
                    self.undo()
                    if ttype != TokenType.INVALID:
                        self.emit(token, ttype, val)
                    self.emit(token, TokenType.DOT, ".")
            elif ttype != TokenType.INVALID:
                self.undo()
                self.emit(token, ttype, val)
            elif c.isalpha() or c == '_':
                val = self.scan_identifier(c)
                self.emit(token, TokenType.IDENTIFIER, val)
            else:
                raise SyntaxError("Invalid token: {}".format(c))

        return self.get_token()


if __name__ == '__main__':
    s = Scan(sys.argv[1])
    while True:
        t = s.scan()
        if t is None:
            break
        if t.tokentype == TokenType.INVALID:
            print("*** ERROR INVALID")
        print(t)
