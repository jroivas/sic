#!/usr/bin/env python3

import sys
from enum import Enum

class EOFError(Exception):
    pass

class SyntaxError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)

class ParserError(Exception):
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
    def __init__(self, line, col, tokentype=TokenType.INVALID, value=''):
        self.line = line
        self.col = col
        self.tokentype = tokentype
        self.value = value

    def set_val(self, value):
        self.value = value

    def __repr__(self):
        return 'Token({}, {} @{},{})'.format(self.tokentype, self.value, self.line, self.col)

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
        self.token_line = 0
        self.token_col = 0
        self.tokens = []

    def next(self):
        """
        Take next character
        """
        if self.idx >= self.data_len:
            raise EOFError
        c = self.data[self.idx]
        self.col += 1
        if chr(c) == '\n':
            self.line += 1
            self.col = 0
        self.idx += 1
        return chr(c)

    def peek(self):
        """
        Peek what is the next character
        """
        if self.idx >= self.data_len:
            return None
        return chr(self.data[self.idx])

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
        if chr(self.data[self.idx]) == '\n':
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

    def scan_decimal(self, c):
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

    def emit(self, tokentype, value):
        token = Token(self.token_line, self.token_col, tokentype, value)
        self.tokens.append(token)
        self.token_line = self.line
        self.token_col = self.col

    def get_token(self):
        if not self.tokens:
            return None
        return self.tokens.pop(0)

    def scan_plus(self, c):
        c2 = self.next()
        if c2 =='+':
            self.emit(TokenType.PLUSPLUS, c + c2)
        else:
            self.undo()
            self.emit(TokenType.PLUS, c)

    def scan_minus(self, c):
        c2 = self.next()
        if c2 =='-':
            self.emit(TokenType.MINUSMINUS, c + c2)
        else:
            self.undo()
            self.emit(TokenType.MINUS, c)

    def scan_number(self, c):
        val = c
        ttype = TokenType.INVALID

        if c.isdigit():
            ttype = TokenType.INT_LIT
            val = self.scan_decimal(c)
            c = self.next()

        if c == '.':
            p = self.peek()
            if p is not None and (p.isdigit() or self.is_space(p)):
                c = self.next()
                frac = self.scan_fraction(c)
                if val == '.':
                    val = 0
                self.emit(TokenType.DEC_LIT, [val, frac])
                return True
        elif ttype != TokenType.INVALID:
            self.undo()
            self.emit(ttype, val)
            return True

        return False

    def scan_identifier(self, c):
        if c == '.':
            c = self.next()
            if c == '.':
                c = self.next()
                if c == '.':
                    self.emit(TokenType.ELLIPSIS, "...")
                else:
                    raise SyntaxError("Got two dots, invalid syntax")
            elif c.isdigit() or self.is_space(c):
                raise ParserError("Expected non number, compiler error")
            else:
                self.undo()
                self.emit(TokenType.DOT, ".")
        elif c.isalpha() or c == '_':
            val = self.scan_identifier(c)
            self.emit(TokenType.IDENTIFIER, val)
        else:
            return False

        return True

    def scan(self):
        if self.tokens:
            return self.get_token()

        try:
            c = self.skip()
        except EOFError:
            return None

        self.token_line = self.line
        self.token_col = self.col
        ttype = TokenType.INVALID

        if c == '+':
            self.scan_plus(c)
        elif c == '-':
            self.scan_minus(c)
        elif c == ';':
            self.emit(TokenType.SEMI, c)
        elif self.scan_number(c):
            pass
        elif self.scan_identifier(c):
            pass
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
