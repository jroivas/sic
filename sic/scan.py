from sic.token import Token, TokenType
from sic.errors import EOFError, SyntaxError, ParserError

from ply import lex
from ply.lex import TOKEN


class Scan:
    def __init__(self, fname=""):
        self.fname = fname
        self.success = True
        self.types = []
        self.filestack = []
        self.origname = ""

        self.lexer = lex.lex(object=self)
        if fname:
            with open(fname, "r") as fd:
                self.lexer.input(fd.read())

    def add_type(self, new_type):
        self.types.append(new_type)

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
        "DEFAULT",
        "RETURN",
        "TYPEDEF",
        "EXTERN",
        "STATIC",
        "AUTO",
        "REGISTER",
        "CONST",
        "RESTRICT",
        "VOLATILE",
        "IF",
        "ELSE",
        "SWITCH",
        "CASE",
        "WHILE",
        "DO",
        "FOR",
        "SIZEOF",
        "STRUCT",
        "UNION",
        "ENUM",
        "TYPE_NAME",
        "INLINE",
        "__BUILTIN_VA_ARG",
        "VA_ARG",
    ]
    keywords_as_is = [
        "_Bool",
        "_Complex",
        "_Atomic",
        "_Alignas",
    ]

    keyword_map = {}
    for kw in keywords:
        keyword_map[kw.lower()] = kw
    for kw in keywords_as_is:
        keyword_map[kw] = kw

    tokens = keywords + keywords_as_is + [
        "PLUS",
        "PLUSPLUS",
        "MINUS",
        "MINUSMINUS",
        "SEMI",
        "INT_LIT",
        "FRAC_LIT",
        "DOT",
        "IDENTIFIER",
        "ELLIPSIS",
        "STAR",
        "SLASH",
        "COMMENT",
        "MULTICOMMENT",
        "MOD",
        "XOR",
        "COMMA",
        "ROUND_OPEN",
        "ROUND_CLOSE",
        "CURLY_OPEN",
        "CURLY_CLOSE",
        "SQUARE_OPEN",
        "SQUARE_CLOSE",
        "TILDE",
        "COLON",
        "PTR_OP",
        "AMP",
        "LOG_AND",
        "EQ",
        "EQ_EQ",
        "NOT",
        "EQ_NE",
        "LT",
        "LE",
        "SH_LEFT",
        "GT",
        "GE",
        "SH_RIGHT",
        "OR",
        "LOG_OR",
        "QUESTION",
        "STR_LIT",
        "PREPROCESS",
        "PLUS_EQ",
        "MINUS_EQ",
        "AND_EQ",
        "OR_EQ",
        "XOR_EQ",
        "MUL_EQ",
        "DIV_EQ",
        "LEFT_EQ",
        "MOD_EQ",
        "RIGHT_EQ",
        "PREPROCESSOR",
        "CONSTANT_CHAR",
    ]
    t_PLUS = r"\+"
    t_MINUS = r"-"
    t_PLUSPLUS = r"\+\+"
    t_MINUSMINUS = r"--"
    t_SEMI = r";"
    t_DOT = r"\."
    t_STAR = r"\*"
    t_ELLIPSIS = r"\.\.\."
    t_SLASH = r"/"
    t_MOD = r"%"
    t_XOR = r"\^"
    t_COMMA = r"\,"
    t_ROUND_OPEN = r"\("
    t_ROUND_CLOSE = r"\)"
    t_CURLY_OPEN = r"\{"
    t_CURLY_CLOSE = r"\}"
    t_SQUARE_OPEN = r"\["
    t_SQUARE_CLOSE = r"\]"
    t_TILDE = r"\~"
    t_COLON = r":"
    t_PTR_OP = r"->"
    t_AMP = r"\&"
    t_LOG_AND = r"\&\&"
    t_EQ = r"="
    t_EQ_EQ = r"=="
    t_NOT = r"!"
    t_EQ_NE = r"!="
    t_SH_LEFT = r"<<"
    t_SH_RIGHT = r">>"
    t_LT = r"<"
    t_LE = r"<="
    t_GT = r">"
    t_GE = r">="
    t_OR = r"\|"
    t_LOG_OR = r"\|\|"
    t_QUESTION = r"\?"
    t_PLUS_EQ = r"\+="
    t_MINUS_EQ = r"-="
    t_AND_EQ = r"\&="
    t_OR_EQ = r"\|="
    t_XOR_EQ = r"\^="
    t_MUL_EQ = r"\*="
    t_DIV_EQ = r"/="
    t_MOD_EQ = r"%="
    t_LEFT_EQ = r"<<="
    t_RIGHT_EQ = r">>="
    t_CONSTANT_CHAR = r"'[^\']+'"

    t_ignore = " \t\r\f"

    escape_sequence_start_in_string = r"""(\\[0-9a-zA-Z._~!=&\^\-\\?'"])"""
    string_char = r"""([^"\\\n]|""" + escape_sequence_start_in_string + ")"
    t_STR_LIT = '"' + string_char + '*"'

    def t_newline(self, t):
        r"\n+"
        t.lexer.lineno += len(t.value)
        #print("LINENO", t.lexer.lineno)

    def t_error(self, t):
        print("Illegal character '%s'" % t.value[0])
        self.success = False
        t.lexer.skip(1)

    def t_FRAC_LIT(self, t):
        r"(\d*\.\d+)|(\d+\.)"
        # print("FL", t.value)
        # t.value = float(t.value)
        return t

    def t_INT_LIT(self, t):
        r"(0[xX][0-9a-fA-F]+)|(\d+)"
        # t.value = int(t.value)
        return t

    identifier = r"[a-zA-Z_][0-9a-zA-Z_]*"
    @TOKEN(identifier)
    def t_IDENTIFIER(self, t):
        #r"[a-zA-Z_][0-9a-zA-Z_]*"
        t.type = self.keyword_map.get(t.value, "IDENTIFIER")
        if t.value in self.types:
            #print("MATCH", t.value)
            #t.type = ""
            t.type = "TYPE_NAME"
        #print("IDENTIFIER", t.value, t.type, type(t.type))
        return t

    def t_PREPROCESSOR(self, t):
        r"\#.*\n+"
        # FIXME simple parse of linemarkers
        vals = t.value.strip().split(" ")
        if len(vals) >= 3 and vals[1].isnumeric():
            lineno = int(vals[1])
            fname = vals[2]
            flags = vals[3:]
            if not self.origname and not flags:
                self.origname = fname
            if "1" in flags:
                self.filestack.append(fname)
            elif "2" in flags:
                self.filestack.pop()
            #print(lineno, fname, flags, self.filestack)
            if fname == self.origname:
                t.lexer.lineno = lineno

    def t_COMMENT(self, t):
        r"//.*"
        pass

    def t_MULTICOMMENT(self, t):
        r"/\*[^*]*\*/"
        pass

    def scan(self):
        return self.lexer.token()
