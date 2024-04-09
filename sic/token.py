from enum import Enum

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
    MOD = 15
    XOR = 16
    COMMA = 17
    ROUND_OPEN = 18
    ROUND_CLOSE = 19
    CURLY_OPEN = 20
    CURLY_CLOSE = 21
    SQUARE_OPEN = 22
    SQUARE_CLOSE = 23
    TILDE = 24
    COLON = 25
    PTR_OP = 26
    AMP = 27
    LOG_AND = 28
    EQ = 29
    EQ_EQ = 30
    NOT = 31
    EQ_NE = 32
    LT = 33
    SH_LEFT = 34
    GT = 35
    SH_RIGHT = 36
    OR = 37
    LOG_OR = 38
    QUESTION = 39
    STR_LIT = 40
    PREPROCESS = 41
    PLUS_EQ = 42
    MINUS_EQ = 43
    AND_EQ = 44
    OR_EQ = 45
    XOR_EQ = 46


class Token:
    def __init__(self, line, col, tokentype=TokenType.INVALID, value=""):
        self.line = line
        self.col = col
        self.tokentype = tokentype
        self.value = value

    def set_val(self, value):
        self.value = value

    def __repr__(self):
        return "Token({}, {} @{},{})".format(
            self.tokentype, self.value, self.line, self.col
        )

