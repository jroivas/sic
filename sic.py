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
    FRAC_LIT = 8
    DOT = 9
    IDENTIFIER = 10
    ELLIPSIS = 11
    STAR = 12
    SLASH = 13
    COMMENT = 14

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

    def __init__(self, filename, data=[]):
        self.fname = filename
        self.data = r''
        if data:
            self.data = data
        else:
            with open(self.fname, 'rb') as fd:
                self.data = fd.read()
        self.data_len = len(self.data)
        self.idx = 0
        self.line = 0
        self.col = 0
        #self.colstack = []
        self.token_line = 0
        self.token_col = 0
        self.tokens = []

    def next(self):
        """
        Take next character

        >>> s = Scan("", b"1 + 5")
        >>> s.next()
        '1'
        >>> s.next()
        ' '
        >>> s.next()
        '+'
        >>> s.next()
        ' '
        >>> s.next()
        '5'
        >>> s.next() #doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
         ...
        sic.EOFError
        >>> s = Scan("", b"1\\n\\n2\\n3\\n")
        >>> s.next()
        '1'
        >>> s.next()
        '\\n'
        >>> s.next()
        '\\n'
        >>> s.next()
        '2'
        >>> s.next()
        '\\n'
        >>> s.next()
        '3'
        >>> s.next()
        '\\n'
        >>> s.next() #doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
         ...
        sic.EOFError
        >>> s = Scan("", b"")
        Traceback (most recent call last):
         ...
        FileNotFoundError: [Errno 2] No such file or directory: ''
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

        >>> s = Scan("", b"1")
        >>> s.peek()
        '1'
        >>> s.peek()
        '1'
        >>> s = Scan("", b"a")
        >>> s.idx = 1
        >>> s.peek()
        """
        if self.idx >= self.data_len:
            return None
        return chr(self.data[self.idx])

    def is_space(self, c):
        """
        Check if character is whitespace

        >>> s = Scan("", b"a")
        >>> s.is_space(" ")
        True
        >>> s.is_space("\\t")
        True
        >>> s.is_space("\\n")
        True
        >>> s.is_space("\\r")
        True
        >>> s.is_space("\\f")
        True
        >>> s.is_space("1")
        False
        >>> s.is_space("a")
        False
        >>> s.is_space(None)
        False
        >>> s.is_space("\\n\\t")
        Traceback (most recent call last):
         ...
        sic.ParserError: Expected one character
        """
        if c is None:
            return False
        if len(c) != 1:
            raise ParserError("Expected one character")
        if c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '\f':
            return True
        return False

    def skip(self):
        """
        Take next markable character

        >>> s = Scan("", b"  1 2  3   4     5\\t6\\n7")
        >>> s.skip()
        >>> s.next()
        '1'
        >>> s.skip()
        >>> s.next()
        '2'
        >>> s.skip()
        >>> s.next()
        '3'
        >>> s.skip()
        >>> s.next()
        '4'
        >>> s.skip()
        >>> s.next()
        '5'
        >>> s.skip()
        >>> s.next()
        '6'
        >>> s.skip()
        >>> s.next()
        '7'
        >>> s.skip()
        Traceback (most recent call last):
         ...
        sic.EOFError
        """
        c = self.peek()
        if c is None:
            raise EOFError
        if not self.is_space(c):
            return None
        while self.is_space(c):
            c = self.next()
        self.undo()
        return None

    def undo(self):
        """
        Go back one character

        >>> s = Scan("", b"123456")
        >>> s.next()
        '1'
        >>> s.next()
        '2'
        >>> s.undo()
        >>> s.next()
        '2'
        >>> s.undo()
        >>> s.undo()
        >>> s.next()
        '1'
        >>> s.undo()
        >>> s.undo()
        Traceback (most recent call last):
         ...
        ValueError: Invalid undo
        >>> s = Scan("", b"1\\n2\\n3")
        >>> s.next()
        '1'
        >>> s.next()
        '\\n'
        >>> s.next()
        '2'
        >>> s.line
        1
        >>> s.next()
        '\\n'
        >>> s.line
        2
        >>> s.col
        0
        >>> s.undo()
        >>> s.line
        1
        """
        """
        FIXME
        >>> s.col
        1
        """
        if self.idx == 0:
            raise ValueError("Invalid undo")
        self.idx -= 1
        if chr(self.data[self.idx]) == '\n':
            self.line -= 1
        elif self.col:
            self.col -= 1

    def scan_fraction(self):
        """
        Scan fraction part of the number, return dividend and the divisor as list

        >>> s = Scan("", b"1234")
        >>> s.scan_fraction()
        [1234, 10000]
        >>> s = Scan("", b"555")
        >>> s.scan_fraction()
        [555, 1000]
        >>> s = Scan("", b"555.")
        >>> s.scan_fraction()
        [555, 1000]
        >>> s = Scan("", b"543 5")
        >>> s.scan_fraction()
        [543, 1000]
        >>> s = Scan("", b"0")
        >>> s.scan_fraction()
        [0, 10]
        """
        tmp = '0'
        div = 1

        c = self.peek()
        while c is not None and c.lower() in self.numbers:
            tmp += self.next()
            c = self.peek()
            div *= 10

        return [int(tmp), div]

    def scan_decimal(self):
        """
        Scan decimal number

        >>> s = Scan("", b"1234")
        >>> s.scan_decimal()
        1234
        >>> s = Scan("", b"0x123")
        >>> s.scan_decimal()
        291
        >>> s = Scan("", b"0123")
        >>> s.scan_decimal()
        83
        >>> s = Scan("", b"0o124")
        >>> s.scan_decimal()
        84
        >>> s = Scan("", b"0")
        >>> s.scan_decimal()
        0
        """
        radix = 10
        tmp = ''

        c = self.peek()
        if c is None:
            return None
        if c == '0':
            tmp += self.next()
            c = self.peek()
            if c == 'x':
                tmp += self.next()
                c = self.peek()
                radix = 16
            elif c == 'o':
                self.next()
                c = self.peek()
                radix = 8
            else:
                radix = 8

        while c is not None and c.lower() in self.numbers:
            tmp += self.next()
            c = self.peek()

        return int(tmp, radix)

    def scan_identifier(self):
        """
        Scan identifier

        >>> s = Scan("", b"tst")
        >>> s.scan_identifier()
        'tst'
        >>> s = Scan("", b"some other identifier")
        >>> s.scan_identifier()
        'some'
        >>> s.skip()
        >>> s.scan_identifier()
        'other'
        >>> s.skip()
        >>> s.scan_identifier()
        'identifier'
        """
        tmp = ''

        c = self.peek()
        while c is not None and (c.isalpha() or c.isdigit() or c == '_'):
            tmp += self.next()
            c = self.peek()

        return tmp

    def emit(self, tokentype, value):
        """
        Emit new token, place it into queue

        >>> s = Scan("", b"tst")
        >>> len(s.tokens)
        0
        >>> s.emit(TokenType.PLUS, "+")
        >>> len(s.tokens)
        1
        >>> s.emit(TokenType.MINUS, "-")
        >>> len(s.tokens)
        2
        """
        token = Token(self.token_line, self.token_col, tokentype, value)
        self.tokens.append(token)
        self.token_line = self.line
        self.token_col = self.col

    def get_token(self):
        """
        Get token from the queue

        >>> s = Scan("", b"tst")
        >>> s.get_token()
        >>> s.emit(TokenType.IDENTIFIER, "tst")
        >>> s.get_token()
        Token(TokenType.IDENTIFIER, tst @0,0)
        """
        if not self.tokens:
            return None
        return self.tokens.pop(0)

    def scan_plus(self):
        """
        Scan plus and plusplus

        >>> s = Scan("", b"+")
        >>> s.scan_plus()
        >>> s.get_token()
        Token(TokenType.PLUS, + @0,0)
        >>> s = Scan("", b"++")
        >>> s.scan_plus()
        >>> s.get_token()
        Token(TokenType.PLUSPLUS, ++ @0,0)
        >>> s = Scan("", b"+=")
        >>> s.scan_plus()
        >>> s.get_token()
        Token(TokenType.PLUS, + @0,0)
        """
        c = self.next()
        c2 = self.peek()
        if c2 =='+':
            c2 = self.next()
            self.emit(TokenType.PLUSPLUS, c + c2)
        else:
            self.emit(TokenType.PLUS, c)

    def scan_minus(self):
        """
        Scan minus and minusminus

        >>> s = Scan("", b"-")
        >>> s.scan_minus()
        >>> s.get_token()
        Token(TokenType.MINUS, - @0,0)
        >>> s = Scan("", b"--")
        >>> s.scan_minus()
        >>> s.get_token()
        Token(TokenType.MINUSMINUS, -- @0,0)
        >>> s = Scan("", b"-+")
        >>> s.scan_minus()
        >>> s.get_token()
        Token(TokenType.MINUS, - @0,0)
        """
        c = self.next()
        c2 = self.peek()
        if c2 =='-':
            c2 = self.next()
            self.emit(TokenType.MINUSMINUS, c + c2)
        else:
            self.emit(TokenType.MINUS, c)

    def scan_number(self):
        """
        Read number, decimal or fraction

        >>> s = Scan("", b"1.5")
        >>> s.scan_number()
        True
        >>> s.get_token()
        Token(TokenType.FRAC_LIT, [1, [5, 10]] @0,0)
        >>> s = Scan("", b"66.66.66")
        >>> s.scan_number()
        True
        >>> s.get_token()
        Token(TokenType.FRAC_LIT, [66, [66, 100]] @0,0)
        """
        ttype = TokenType.INVALID

        c = self.peek()
        val = c
        if c.isdigit():
            ttype = TokenType.INT_LIT
            val = self.scan_decimal()
            c = self.peek()

        if c == '.':
            p = self.next()
            p = self.peek()
            if p is not None and (p.isdigit() or self.is_space(p)):
                frac = self.scan_fraction()
                if val == '.':
                    val = 0
                self.emit(TokenType.FRAC_LIT, [val, frac])
                return True
        elif ttype != TokenType.INVALID:
            self.emit(ttype, val)
            return True

        return False

    def scan_ellipsis_identifier(self):
        """
        Scan ellipsis or identifier

        >>> s = Scan("", b"...")
        >>> s.scan_ellipsis_identifier()
        True
        >>> s.get_token()
        Token(TokenType.ELLIPSIS, ... @0,0)
        >>> s = Scan("", b"some123 other third42")
        >>> s.scan_ellipsis_identifier()
        True
        >>> s.skip()
        >>> s.scan_ellipsis_identifier()
        True
        >>> s.skip()
        >>> s.scan_ellipsis_identifier()
        True
        >>> s.get_token()
        Token(TokenType.IDENTIFIER, some123 @0,0)
        >>> s.get_token()
        Token(TokenType.IDENTIFIER, other @0,7)
        >>> s.get_token()
        Token(TokenType.IDENTIFIER, third42 @0,13)
        """
        c = self.peek()
        if c == '.':
            c = self.next()
            c = self.peek()
            if c == '.':
                c = self.next()
                c = self.peek()
                if c == '.':
                    self.emit(TokenType.ELLIPSIS, "...")
                else:
                    raise SyntaxError("Got two dots, invalid syntax")
            elif c.isdigit() or self.is_space(c):
                raise ParserError("Expected non number, compiler error")
            else:
                self.emit(TokenType.DOT, ".")
        elif c.isalpha() or c == '_':
            val = self.scan_identifier()
            self.emit(TokenType.IDENTIFIER, val)
        else:
            return False

        return True

    def scan_slash(self):
        """
        >>> s = Scan("", b"// tst\\nnewline")
        >>> s.scan_slash()
        >>> s.get_token()
        Token(TokenType.COMMENT, // tst @0,0)
        >>> s = Scan("", b"/* multi line\\ncomment */")
        >>> s.scan_slash()
        >>> s.get_token()
        Token(TokenType.COMMENT, /* multi line
        comment */ @0,0)
        >>> s = Scan("", b"/")
        >>> s.scan_slash()
        >>> s.get_token()
        Token(TokenType.SLASH, / @0,0)
        """
        c = self.next()
        c = self.peek()
        if c == "/":
            txt = "/"
            # This is comment until the end of line
            while c != "\n" and c != "\r":
                txt += self.next()
                c = self.peek()
            c = self.next()
            self.emit(TokenType.COMMENT, txt)
        elif c == "*":
            txt = "/*"
            # Comment until we get */
            c = self.next()
            while c is not None:
                c = self.peek()
                if c is None:
                    return
                if c == "*":
                    self.next()
                    c = self.peek()
                    if c == "/":
                        txt += '*/'
                        break
                c = self.next()
                txt += c
            self.emit(TokenType.COMMENT, txt)
        else:
            self.emit(TokenType.SLASH, "/")


    def scan(self):
        """
        >>> s = Scan("", b"some test 42 5.4 +")
        >>> s.scan()
        Token(TokenType.IDENTIFIER, some @0,0)
        >>> s.scan()
        Token(TokenType.IDENTIFIER, test @0,5)
        >>> s.scan()
        Token(TokenType.INT_LIT, 42 @0,10)
        >>> s.scan()
        Token(TokenType.FRAC_LIT, [5, [4, 10]] @0,13)
        >>> s.scan()
        Token(TokenType.PLUS, + @0,17)
        >>> s.scan()
        """
        if self.tokens:
            return self.get_token()

        try:
            self.skip()
        except EOFError:
            return None

        self.token_line = self.line
        self.token_col = self.col
        ttype = TokenType.INVALID
        c = self.peek()

        if c == '+':
            self.scan_plus()
        elif c == '-':
            self.scan_minus()
        elif c == ';':
            self.emit(TokenType.SEMI, self.next())
        elif c == '*':
            self.emit(TokenType.STAR, self.next())
        elif c == '/':
            self.scan_slash()
        elif self.scan_number():
            pass
        elif self.scan_ellipsis_identifier():
            pass
        else:
            self.emit(TokenType.INVALID, self.next())
            #raise SyntaxError("Invalid token: {}".format(c))

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
