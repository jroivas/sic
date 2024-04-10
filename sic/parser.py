from sic.token import TokenType, Token
from sic.scan import Scan
from sic.ast import AstType, AstNode, AstOpNode

from ply import yacc

class Parser:
    def __init__(self, scanner, debug=False):
        self.tokens = scanner.tokens
        self.scanner = scanner
        self.yacc = yacc.yacc(
            module=self,
            start='translation_unit'
            )
        self.debug = debug

    def success(self):
        return self.scanner.success

    def readfile(self, fname):
        with open(fname, "r") as fd:
            return fd.read()

    def parse(self, filename, data=None):
        self.scanner.fname = filename
        if data is None and filename:
            data = self.readfile(filename)
        return self.yacc.parse(
            input=data,
            lexer=self.scanner.lexer,
            debug=self.debug)

    def p_empty(self, p):
        """ empty : """
        p[0] = None

    def p_translation_unit(self, p):
        """ translation_unit : external_declarations
                             | empty
        """
        if p[1] is None:
            p[0] = AstNode(AstType.ROOT, [])
        else:
            p[0] = AstNode(AstType.ROOT, p[1])

    def p_external_declarations_1(self, p):
        """ external_declarations : external_declaration """
        p[0] = p[1]

    def p_external_declarations_2(self, p):
        """ external_declarations : external_declarations external_declaration """
        p[0] = [p[1], p[2]]

    def p_external_declaration_1(self, p):
        """ external_declaration : declaration """
        p[0] = p[1]

    def p_external_declaration_2(self, p):
        """ external_declaration : statement_list """
        p[0] = p[1]

    def p_declaration_1(self, p):
        """ declaration : declaration_specifiers SEMI """
        p[0] = p[1]

    def p_declaration_2(self, p):
        """ declaration : declaration_specifiers init_declarator_list SEMI """
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_1(self, p):
        """ declaration_specifiers : type_specifier """
        p[0] = p[1]

    def p_declaration_specifiers_2(self, p):
        """ declaration_specifiers : type_specifier declaration_specifiers"""
        p[0] = [p[1], p[2]]

    def p_type_specifier(self, p):
        """ type_specifier : VOID
                           | CHAR
                           | SHORT
                           | INT
                           | LONG
                           | FLOAT
                           | DOUBLE
                           | SIGNED
                           | UNSIGNED"""
        p[0] = AstNode(AstType.TYPE, p[1])

    def p_init_declarator_list_1(self, p):
        """ init_declarator_list : init_declarator"""
        #p[0] = [p[1]]
        p[0] = p[1]

    def p_init_declarator_list_2(self, p):
        """ init_declarator_list : init_declarator_list COMMA init_declarator"""
        p[0] = [p[1], p[3]]

    def p_init_declarator_1(self, p):
        """ init_declarator : declarator"""
        p[0] = p[1]

    def p_init_declarator_2(self, p):
        """ init_declarator : declarator EQ initializer"""
        p[0] = [p[1], p[2], p[3]]

    def p_declarator_1(self, p):
        """ declarator : pointer direct_declarator"""
        p[0] = AstNode(AstType.POINTER, p[2])

    def p_declarator_2(self, p):
        """ declarator : direct_declarator"""
        p[0] = p[1]

    def p_pointer_1(self, p):
        """ pointer : STAR"""
        p[0] = AstNode(AstType.POINTER, None)

    def p_pointer_2(self, p):
        """ pointer : STAR pointer"""
        p[0] = AstNode(AstType.POINTER, p[2])

    #def p_pointer_3(self, p):
    #    """ pointer : STAR type_qualifier_list"""

    #def p_pointer_4(self, p):
    #    """ pointer : STAR type_qualifier_list pointer"""

    def p_direct_declarator_1(self, p):
        """ direct_declarator : IDENTIFIER"""
        p[0] = AstNode(AstType.IDENTIFIER, p[1])

    def p_direct_declarator_2(self, p):
        """ direct_declarator : ROUND_OPEN declarator ROUND_CLOSE"""
        p[0] = [p[2]]

    def p_initializer(self, p):
        """ initializer : assignment_expression"""
        p[0] = p[1]

    def p_statement_list_1(self, p):
        """ statement_list : statement """
        p[0] = [p[1]]

    def p_statement_list_2(self, p):
        """ statement_list : statement_list statement """
        p[1].extend(p[2])
        p[0] = p[1]

    def p_statement_1(self, p):
        """ statement : compound_statement """
        p[0] = p[1]

    def p_statement_2(self, p):
        """ statement : expression_statement """
        p[0] = p[1]

    def p_compound_statement_1(self, p):
        """ compound_statement : CURLY_OPEN CURLY_CLOSE """
        p[0] = AstNode(AstType.Block, [])

    def p_compound_statement_2(self, p):
        """ compound_statement : CURLY_OPEN statement_list CURLY_CLOSE """
        p[0] = AstNode(AstType.Block, p[2])

    def p_expression_statement_1(self, p):
        """ expression_statement : expression SEMI """
        p[0] = p[1]

    def p_expression_statement_2(self, p):
        """ expression_statement : expression_statement expression SEMI """
        #p[1].extend(p[2])
        #p[1].extend(p[3])
        p[0] = [p[1], p[2]]

    def p_expression(self, p):
        """ expression : conditional_expression """
        p[0] = p[1]

    def p_assignment_expression_1(self, p):
        """ assignment_expression : conditional_expression"""
        p[0] = p[1]

    def p_assignment_expression_2(self, p):
        """ assignment_expression : unary_expression assignment_operator assignment_expression"""
        p[0] = p[1]

    def p_assignment_operator(self, p):
        """ assignment_operator : EQ
                                | MUL_EQ
                                | DIV_EQ
                                | MOD_EQ
                                | PLUS_EQ
                                | MINUS_EQ
                                | LEFT_EQ
                                | RIGHT_EQ
                                | AND_EQ
                                | XOR_EQ
                                | OR_EQ
                                """
        p[0] = p[1]

    def p_conditional_expression(self, p):
        """ conditional_expression : logical_or_expression """
        p[0] = p[1]

    def p_logical_or_expression(self, p):
        """ logical_or_expression : logical_and_expression """
        p[0] = p[1]

    def p_logical_and_expression(self, p):
        """ logical_and_expression : inclusive_or_expression """
        p[0] = p[1]

    def p_inclusive_or_expression(self, p):
        """ inclusive_or_expression : exclusive_or_expression """
        p[0] = p[1]

    def p_exclusive_or_expression(self, p):
        """ exclusive_or_expression : and_expression """
        p[0] = p[1]

    def p_and_expression(self, p):
        """ and_expression : equality_expression """
        p[0] = p[1]

    def p_equality_expression(self, p):
        """ equality_expression : relational_expression """
        p[0] = p[1]

    def p_relational_expression(self, p):
        """ relational_expression : shift_expression"""
        p[0] = p[1]

    def p_shift_expression(self, p):
        """ shift_expression : additive_expression """
        p[0] = p[1]

    def p_additive_expression_1(self, p):
        """ additive_expression : multiplicative_expression"""
        p[0] = p[1]

    def p_additive_expression_2(self, p):
        """ additive_expression : additive_expression PLUS multiplicative_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_additive_expression_3(self, p):
        """ additive_expression : additive_expression MINUS multiplicative_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_1(self, p):
        """ multiplicative_expression : cast_expression"""
        p[0] = p[1]

    def p_multiplicative_expression_2(self, p):
        """ multiplicative_expression : multiplicative_expression STAR cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_3(self, p):
        """ multiplicative_expression : multiplicative_expression SLASH cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_4(self, p):
        """ multiplicative_expression : multiplicative_expression MOD cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_cast_expression(self, p):
        """ cast_expression : unary_expression"""
        p[0] = p[1]

    def p_unary_expression_1(self, p):
        """ unary_expression : postfix_expression """
        p[0] = p[1]

    def p_unary_expression_2(self, p):
        """ unary_expression : PLUS cast_expression """
        p[0] = AstOpNode(p[1], "0", p[2])

    def p_unary_expression_3(self, p):
        """ unary_expression : MINUS cast_expression """
        p[0] = AstOpNode(p[1], "0", p[2])

    def p_postfix_expression(self, p):
        """ postfix_expression : primary_expression """
        p[0] = p[1]

    def p_primary_expression_1(self, p):
        """ primary_expression : FRAC_LIT"""
        p[0] = AstNode(AstType.FRAC_LIT, p[1])

    def p_primary_expression_2(self, p):
        """ primary_expression : INT_LIT """
        p[0] = AstNode(AstType.INT_LIT, p[1])

    def p_primary_expression_3(self, p):
        """ primary_expression : STR_LIT """
        p[0] = AstNode(AstType.STR_LIT, p[1])

    def p_primary_expression_4(self, p):
        """ primary_expression : IDENTIFIER """
        p[0] = AstNode(AstType.IDENTIFIER, p[1])

