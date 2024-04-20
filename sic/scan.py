from sic.token import Token, TokenType
from sic.errors import EOFError, SyntaxError, ParserError

from ply import lex

class Scan:
    def __init__(self, fname=""):
        self.fname = fname
        self.success = True

        self.lexer = lex.lex(object=self)
        if fname:
            with open(fname, "r") as fd:
                self.lexer.input(fd.read())

    keywords = [
        "VOID",
        "CHAR",
        "SHORT",
        "INT",
        "LONG",
        "FLOAT",
        "DOUBLE",
        "SIGNED",
        "UNSIGNED",

        "GOTO",
        "CONTINUE",
        "BREAK",
        "RETURN",

        "TYPEDEF",
        "EXTERN",
        "STATIC",
        "AUTO",
        "REGISTER",

        "CONST",
        "VOLATILE",

        "IF",
        "ELSE",
        "SWITCH",
        "CASE",
        "WHILE",
        "DO",
    ]

    keyword_map = {}
    for kw in keywords:
        keyword_map[kw.lower()] = kw

    tokens = keywords + [
        'PLUS',
        'PLUSPLUS',
        'MINUS',
        'MINUSMINUS',
        'SEMI',
        'INT_LIT',
        'FRAC_LIT',
        'DOT',
        'IDENTIFIER',
        'ELLIPSIS',
        'STAR',
        'SLASH',
        'COMMENT',
        'MULTICOMMENT',
        'MOD',
        'XOR',
        'COMMA',
        'ROUND_OPEN',
        'ROUND_CLOSE',
        'CURLY_OPEN',
        'CURLY_CLOSE',
        'SQUARE_OPEN',
        'SQUARE_CLOSE',
        'TILDE',
        'COLON',
        'PTR_OP',
        'AMP',
        'LOG_AND',
        'EQ',
        'EQ_EQ',
        'NOT',
        'EQ_NE',
        'LT',
        'LE',
        'SH_LEFT',
        'GT',
        'GE',
        'SH_RIGHT',
        'OR',
        'LOG_OR',
        'QUESTION',
        'STR_LIT',
        'PREPROCESS',
        'PLUS_EQ',
        'MINUS_EQ',
        'AND_EQ',
        'OR_EQ',
        'XOR_EQ',
        'MUL_EQ',
        'DIV_EQ',
        'LEFT_EQ',
        'MOD_EQ',
        'RIGHT_EQ',
        'IDENTIFIER',
    ]
    t_PLUS = r'\+'
    t_MINUS = r'-'
    t_PLUSPLUS = r'\+\+'
    t_MINUSMINUS = r'--'
    t_SEMI = r';'
    t_DOT = r'\.'
    t_STAR = r'\*'
    t_ELLIPSIS = r'\.\.\.'
    t_SLASH = r'/'
    t_COMMENT = r'//.*'
    t_MULTICOMMENT = r'/\*[^*]*\*/'
    t_MOD = r'%'
    t_XOR = r'\^'
    t_COMMA = r'\,'
    t_ROUND_OPEN = r'\('
    t_ROUND_CLOSE = r'\)'
    t_CURLY_OPEN = r'\{'
    t_CURLY_CLOSE = r'\}'
    t_SQUARE_OPEN = r'\['
    t_SQUARE_CLOSE = r'\]'
    t_TILDE = r'\~'
    t_COLON = r':'
    t_PTR_OP = r'->'
    t_AMP = r'\&'
    t_LOG_AND = r'\&\&'
    t_EQ = r'='
    t_EQ_EQ = r'=='
    t_NOT = r'!'
    t_EQ_NE = r'!='
    t_SH_LEFT = r'<<'
    t_SH_RIGHT = r'>>'
    t_LT = r'<'
    t_LE = r'<='
    t_GT = r'>'
    t_GE = r'>='
    t_OR = r'\|'
    t_LOG_OR = r'\|\|'
    t_QUESTION = r'\?'
    t_PLUS_EQ = r'\+='
    t_MINUS_EQ = r'-='
    t_AND_EQ = r'\&='
    t_OR_EQ = r'\|='
    t_XOR_EQ = r'\^='
    t_MUL_EQ = r'\*='
    t_DIV_EQ = r'/='
    t_MOD_EQ = r'%='
    t_LEFT_EQ = r'<<='
    t_RIGHT_EQ = r'>>='

    t_ignore = " \t\r\f"

    escape_sequence_start_in_string = r"""(\\[0-9a-zA-Z._~!=&\^\-\\?'"])"""
    string_char = r"""([^"\\\n]|"""+escape_sequence_start_in_string+')'
    t_STR_LIT = '"'+ string_char+ '*"'

    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    def t_error(self, t):
        print("Illegal character '%s'" % t.value[0])
        self.success = False
        t.lexer.skip(1)

    def t_FRAC_LIT(self, t):
        r'(\d*\.\d+)|(\d+\.)'
        #print("FL", t.value)
        #t.value = float(t.value)
        return t

    def t_INT_LIT(self, t):
        r'(0[xX][0-9a-fA-F]+)|(\d+)'
        #t.value = int(t.value)
        return t

    def t_IDENTIFIER(self, t):
        r'[a-zA-Z][0-9a-zA-Z]*'
        t.type = self.keyword_map.get(t.value, "IDENTIFIER")
        #print("IDENTIFIER", t.value, t.type)
        return t

    def scan(self):
        return self.lexer.token()

class oldScan:
    numbers = "0123456789abcdef"

    token_map = {
        ";": TokenType.SEMI,
        "*": TokenType.STAR,
        "%": TokenType.MOD,
        "^": {
            "": TokenType.XOR,
            "=": TokenType.XOR_EQ,
        },
        ",": TokenType.COMMA,
        "(": TokenType.ROUND_OPEN,
        ")": TokenType.ROUND_CLOSE,
        "{": TokenType.CURLY_OPEN,
        "}": TokenType.CURLY_CLOSE,
        "[": TokenType.SQUARE_OPEN,
        "]": TokenType.SQUARE_CLOSE,
        "~": TokenType.TILDE,
        ":": TokenType.COLON,
        "?": TokenType.QUESTION,
        "+": {
            "": TokenType.PLUS,
            "+": TokenType.PLUSPLUS,
            "=": TokenType.PLUS_EQ,
        },
        "-": {
            "": TokenType.MINUS,
            "-": TokenType.MINUSMINUS,
            ">": TokenType.PTR_OP,
            "=": TokenType.MINUS_EQ,
        },
        "&": {
            "": TokenType.AMP,
            "&": TokenType.LOG_AND,
            "=": TokenType.AND_EQ,
        },
        "=": {
            "": TokenType.EQ,
            "=": TokenType.EQ_EQ,
        },
        "!": {
            "": TokenType.NOT,
            "=": TokenType.EQ_NE,
        },
        "<": {
            "": TokenType.LT,
            "<": TokenType.SH_LEFT,
        },
        ">": {
            "": TokenType.GT,
            ">": TokenType.SH_RIGHT,
        },
        "|": {
            "": TokenType.OR,
            "|": TokenType.LOG_OR,
            "=": TokenType.OR_EQ,
        },
    }

    def __init__(self, filename, data=[]):
        self.fname = filename
        self.data = r""
        if data:
            self.data = data
        else:
            with open(self.fname, "rb") as fd:
                self.data = fd.read()
        self.data_len = len(self.data)
        self.idx = 0
        self.line = 0
        self.col = 0
        # self.colstack = []
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
        sic.errors.EOFError
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
        sic.errors.EOFError
        >>> s = Scan("", b"")
        Traceback (most recent call last):
         ...
        FileNotFoundError: [Errno 2] No such file or directory: ''
        """
        if self.idx >= self.data_len:
            raise EOFError
        c = self.data[self.idx]
        self.col += 1
        if chr(c) == "\n":
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
        sic.errors.ParserError: Expected one character
        """
        if c is None:
            return False
        if len(c) != 1:
            raise ParserError("Expected one character")
        if c == " " or c == "\t" or c == "\n" or c == "\r" or c == "\f":
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
        sic.errors.EOFError
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
        if chr(self.data[self.idx]) == "\n":
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
        tmp = "0"
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
        tmp = ""

        c = self.peek()
        if c is None:
            return None
        if c == "0":
            tmp += self.next()
            c = self.peek()
            if c == "x":
                tmp += self.next()
                c = self.peek()
                radix = 16
            elif c == "o":
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
        tmp = ""

        c = self.peek()
        while c is not None and (c.isalpha() or c.isdigit() or c == "_"):
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

        if c == ".":
            p = self.next()
            p = self.peek()
            if p is not None and (p.isdigit() or self.is_space(p)):
                frac = self.scan_fraction()
                if val == ".":
                    val = 0
                self.emit(TokenType.FRAC_LIT, [val, frac])
                return True
            else:
                # Next one is not digit or space, undo the dot
                self.undo()
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
        if c == ".":
            c = self.next()
            c = self.peek()
            if c == ".":
                c = self.next()
                c = self.peek()
                if c == ".":
                    self.emit(TokenType.ELLIPSIS, "...")
                else:
                    raise SyntaxError("Got two dots, invalid syntax")
            elif c.isdigit() or self.is_space(c):
                raise ParserError("Expected non number, compiler error")
            else:
                self.emit(TokenType.DOT, ".")
        elif c.isalpha() or c == "_":
            val = self.scan_identifier()
            self.emit(TokenType.IDENTIFIER, val)
        else:
            return False

        return True

    def solve_escape(self, val):
        v = val.encode("utf-8")
        if not v or v == 0:
            return -1

        if v[0] != ord("\\"):
            return v[0]

        nc = v[1]
        if nc == ord("n"):
            return ord("\n")
        elif nc == ord("r"):
            return ord("\r")
        elif nc == ord("t"):
            return ord("\t")
        elif nc == ord("0"):
            return 0
        elif nc == ord("\\"):
            return ord("\\")
        elif nc == ord("a"):
            return ord("\a")
        elif nc == ord("b"):
            return ord("\b")
        elif nc == ord("f"):
            return ord("\f")
        elif nc == ord("v"):
            return ord("\v")
        elif nc == ord("'"):
            return ord("'")
        elif nc == ord('"'):
            return ord('"')

        return -3

    def scan_string(self, end_char='"', tokentype=TokenType.STR_LIT):
        """
        >>> s = Scan("", b"\\"test\\"")
        >>> s.scan_string()
        >>> s.get_token()
        Token(TokenType.STR_LIT, test @0,0)
        >>> s = Scan("", b"\\"some str 42 lit 4.4\\"")
        >>> s.scan_string()
        >>> s.get_token()
        Token(TokenType.STR_LIT, some str 42 lit 4.4 @0,0)
        >>> s = Scan("", b"'c'")
        >>> s.scan_string("'", TokenType.INT_LIT)
        >>> s.get_token()
        Token(TokenType.INT_LIT, 99 @0,0)
        >>> s = Scan("", b"'\\n'")
        >>> s.scan_string("'", TokenType.INT_LIT)
        >>> s.get_token()
        Token(TokenType.INT_LIT, 10 @0,0)
        """
        self.next()
        c = self.peek()
        val = ""
        while c is not None and c != end_char:
            val += self.next()
            c = self.peek()
        if c == end_char:
            self.next()
        if tokentype == TokenType.INT_LIT:
            val = self.solve_escape(val)
        self.emit(tokentype, val)

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
                        txt += "*/"
                        break
                c = self.next()
                txt += c
            self.emit(TokenType.COMMENT, txt)
        else:
            self.emit(TokenType.SLASH, "/")

    def scan_token(self):
        """
        Scan token defined in token_map

        >>> s = Scan("", b"+")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.PLUS, + @0,0)
        >>> s = Scan("", b"++")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.PLUSPLUS, ++ @0,0)
        >>> s = Scan("", b"+-")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.PLUS, + @0,0)
        >>> s = Scan("", b"+=")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.PLUS_EQ, += @0,0)
        >>> s = Scan("", b"-")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.MINUS, - @0,0)
        >>> s = Scan("", b"--")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.MINUSMINUS, -- @0,0)
        >>> s = Scan("", b"-+")
        >>> s.scan_token()
        True
        >>> s.get_token()
        Token(TokenType.MINUS, - @0,0)
        """
        c = self.peek()
        ttype = self.token_map.get(c, None)

        if ttype is None:
            return False
        val = self.next()

        if type(ttype) == dict:
            c2 = self.peek()
            ttype2 = ttype.get(c2, None)
            if ttype2 == None:
                # Default
                ttype = ttype.get("", None)
                if ttype is None:
                    raise ParserError("Compiler bug, can't find token")
            else:
                ttype = ttype2
                val += self.next()

        self.emit(ttype, val)
        return True

    def scan_preprocessor(self):
        """
        >>> s = Scan("", b"#include <stdio.h>")
        >>> s.scan_preprocessor()
        >>> s.get_token()
        Token(TokenType.PREPROCESS, include <stdio.h> @0,0)
        >>> s = Scan("", b"#    include <stdio.h>")
        >>> s.scan_preprocessor()
        >>> s.get_token()
        Token(TokenType.PREPROCESS, include <stdio.h> @0,0)
        """
        c = self.next()
        res = ""
        while c is not None and c != "\n" and c != "\r":
            res += self.next()
            c = self.peek()
        self.emit(TokenType.PREPROCESS, res.lstrip())

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
        >>> s = Scan("", b",...")
        >>> s.scan()
        Token(TokenType.COMMA, , @0,0)
        >>> s.scan()
        Token(TokenType.ELLIPSIS, ... @0,1)
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

        if c == "/":
            self.scan_slash()
        elif c == '"':
            self.scan_string()
        elif c == "'":
            self.scan_string("'", TokenType.INT_LIT)
        elif c == "#":
            self.scan_preprocessor()
        elif self.scan_token():
            pass
        elif self.scan_number():
            pass
        elif self.scan_ellipsis_identifier():
            pass
        else:
            self.emit(TokenType.INVALID, self.next())
            # raise SyntaxError("Invalid token: {}".format(c))

        return self.get_token()
