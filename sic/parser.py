from sic.token import TokenType, Token
from sic.scan import Scan
from sic.ast import AstType, AstNode, AstOpNode, AstPointer, AstIf

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

    def p_error(self, p):
        print("ERROR: '%s'" % p)

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
        #p[1].extend(p[2])
        #p[0] = p[1]
        p[0] = [p[1], p[2]]

    def p_external_declaration_1(self, p):
        """ external_declaration : function_definition """
        p[0] = p[1]

    def p_external_declaration_2(self, p):
        """ external_declaration : declaration """
        p[0] = p[1]

    def p_external_declaration_3(self, p):
        """ external_declaration : statement_list """
        p[0] = p[1]

    def p_function_definition_1(self, p):
        """ function_definition : declaration_specifiers declarator declaration_list compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3], p[4]])

    def p_function_definition_2(self, p):
        """ function_definition : declaration_specifiers declarator compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3]])

    def p_function_definition_3(self, p):
        """ function_definition : declarator declaration_list compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3]])

    def p_function_definition_4(self, p):
        """ function_definition : declarator compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2]])

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

    def p_declaration_specifiers_3(self, p):
        """ declaration_specifiers : type_qualifier """
        p[0] = p[1]

    def p_declaration_specifiers_4(self, p):
        """ declaration_specifiers : type_qualifier declaration_specifiers"""
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
        p[0] = [p[1], p[2]]

    def p_declarator_2(self, p):
        """ declarator : direct_declarator"""
        p[0] = p[1]

    def p_pointer_1(self, p):
        """ pointer : STAR"""
        p[0] = AstPointer(None)

    def p_pointer_2(self, p):
        """ pointer : STAR type_qualifier_list"""
        p[0] = AstPointer(p[2])

    def p_pointer_3(self, p):
        """ pointer : STAR pointer"""
        if type(p[2]) != AstPointer:
            raise ValueError("Invalid pointer")
        p[2].lvl += 1
        p[0] = p[2]

    def p_pointer_4(self, p):
        """ pointer : STAR type_qualifier_list pointer"""
        p[0] = AstPointer([p[2], p[3]])

    def p_type_qualifier_list_1(self, p):
        """ type_qualifier_list : type_qualifier """
        p[0] = p[1]

    def p_type_qualifier_list_2(self, p):
        """ type_qualifier_list : type_qualifier_list type_qualifier """
        p[0] = [p[1], p[2]]

    def p_type_qualifier(self, p):
        """ type_qualifier : CONST
                           | VOLATILE """
        p[0] = AstNode(AstType.TYPE_QUAL, p[1])

    def p_parameter_type_list_1(self, p):
        """ parameter_type_list : parameter_list"""
        p[0] = [p[1]]

    def p_parameter_type_list_2(self, p):
        """ parameter_type_list : parameter_list COMMA ELLIPSIS"""
        p[1].extend(p[2])
        p[0] = p[1]

    def p_parameter_list_1(self, p):
        """ parameter_list : parameter_declaration"""
        p[0] = [p[1]]

    def p_parameter_list_2(self, p):
        """ parameter_list : parameter_list COMMA parameter_declaration"""
        p[1].extend(p[2])
        p[0] = p[1]

    def p_parameter_declaration_1(self, p):
        """ parameter_declaration : declaration_specifiers declarator"""
        p[0] = [p[1], p[2]]

    def p_parameter_declaration_2(self, p):
        """ parameter_declaration : declaration_specifiers abstract_declarator"""
        p[0] = [p[1], p[2]]

    def p_parameter_declaration_3(self, p):
        """ parameter_declaration : declaration_specifiers"""
        p[0] = p[1]

    def p_abstract_declarator_1(self, p):
        """ abstract_declarator : pointer"""
        p[0] = p[1]

    def p_abstract_declarator_2(self, p):
        """ abstract_declarator : direct_abstract_declarator"""
        p[0] = p[1]

    def p_abstract_declarator_3(self, p):
        """ abstract_declarator : pointer direct_abstract_declarator"""
        p[0] = [p[1], p[2]]

    def p_direct_abstract_declarator_1(self, p):
        """ direct_abstract_declarator : ROUND_OPEN abstract_declarator ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_direct_abstract_declarator_2(self, p):
        """ direct_abstract_declarator : SQUARE_OPEN SQUARE_CLOSE"""
        p[0] = [p[1], p[2]]

    def p_direct_abstract_declarator_3(self, p):
        """ direct_abstract_declarator : SQUARE_OPEN constant_expression SQUARE_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_direct_abstract_declarator_4(self, p):
        """ direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN constant_expression SQUARE_CLOSE"""
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_direct_abstract_declarator_5(self, p):
        """ direct_abstract_declarator : ROUND_OPEN ROUND_CLOSE"""
        p[0] = [p[1], p[2]]

    def p_direct_abstract_declarator_6(self, p):
        """ direct_abstract_declarator : ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_direct_abstract_declarator_7(self, p):
        """ direct_abstract_declarator : direct_abstract_declarator ROUND_OPEN ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_direct_abstract_declarator_8(self, p):
        """ direct_abstract_declarator : direct_abstract_declarator ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_direct_declarator_1(self, p):
        """ direct_declarator : IDENTIFIER"""
        p[0] = AstNode(AstType.IDENTIFIER, p[1])

    def p_direct_declarator_2(self, p):
        """ direct_declarator : ROUND_OPEN declarator ROUND_CLOSE"""
        p[0] = [p[2]]

    def p_direct_declarator_3(self, p):
        """ direct_declarator : direct_declarator SQUARE_OPEN constant_expression SQUARE_CLOSE"""
        p[0] = [p[1], p[2], p[3], p[4]]
        #p[0] = AstNode(AstType.SQUARE, [p[1], p]

    def p_direct_declarator_4(self, p):
        """ direct_declarator : direct_declarator SQUARE_OPEN SQUARE_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_direct_declarator_5(self, p):
        """ direct_declarator : direct_declarator ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_direct_declarator_6(self, p):
        """ direct_declarator : direct_declarator ROUND_OPEN identifier_list ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_direct_declarator_7(self, p):
        """ direct_declarator : direct_declarator ROUND_OPEN ROUND_CLOSE"""
        p[0] = [p[1], p[2], p[3]]

    def p_identifier_list_1(self, p):
        """ identifier_list : IDENTIFIER"""
        p[0] = [p[1]]

    def p_identifier_list_2(self, p):
        """ identifier_list : identifier_list COMMA IDENTIFIER"""
        p[1].extend(p[2])
        p[0] = p[1]

    def p_initializer(self, p):
        """ initializer : assignment_expression"""
        p[0] = p[1]

    def p_statement_list_1(self, p):
        """ statement_list : statement """
        p[0] = [p[1]]

    def p_statement_list_2(self, p):
        """ statement_list : statement_list statement """
        #p[1].extend(p[2])
        p[0] = [p[1], p[2]]

    def p_declaration_list_1(self, p):
        """ declaration_list : declaration"""
        p[0] = [p[1]]

    def p_declaration_list_2(self, p):
        """ declaration_list : declaration_list declaration"""
        #p[0] = [p[1], p[2]]
        if type(p[2]) == list:
            p[1].extend(p[2])
        else:
            p[1] += [p[2]]
        p[0] = p[1]

    #def p_statement_1(self, p):
    #    """ statement : labeled_statement """
    #    p[0] = p[1]

    def p_statement_2(self, p):
        """ statement : compound_statement """
        p[0] = p[1]

    def p_statement_3(self, p):
        """ statement : expression_statement """
        p[0] = p[1]

    def p_statement_4(self, p):
        """ statement : selection_statement """
        p[0] = p[1]

    #def p_statement_5(self, p):
    #    """ statement : iteration_statement """
    #    p[0] = p[1]

    def p_statement_6(self, p):
        """ statement : jump_statement """
        p[0] = p[1]

    def p_selection_statement_1(self, p):
        """ selection_statement : IF ROUND_OPEN expression ROUND_CLOSE statement"""
        p[0] = AstIf(p[3], p[5])

    def p_selection_statement_2(self, p):
        """ selection_statement : IF ROUND_OPEN expression ROUND_CLOSE statement ELSE statement"""
        p[0] = AstIf(p[3], p[5], p[7])

    def p_jump_statement_1(self, p):
        """ jump_statement : RETURN SEMI"""
        p[0] = AstNode(AstType.KEYWORD, p[1])

    def p_jump_statement_2(self, p):
        """ jump_statement : RETURN expression SEMI"""
        p[0] = AstNode(AstType.KEYWORD, [p[1], p[2]])

    def p_compound_statement_1(self, p):
        """ compound_statement : CURLY_OPEN CURLY_CLOSE """
        p[0] = AstNode(AstType.BLOCK, [])

    def p_compound_statement_2(self, p):
        """ compound_statement : CURLY_OPEN statement_list CURLY_CLOSE """
        p[0] = AstNode(AstType.BLOCK, p[2])

    def p_compound_statement_3(self, p):
        """ compound_statement : CURLY_OPEN declaration_list CURLY_CLOSE """
        p[0] = AstNode(AstType.BLOCK, p[2])

    def p_compound_statement_4(self, p):
        """ compound_statement : CURLY_OPEN declaration_list statement_list CURLY_CLOSE """
        p[0] = AstNode(AstType.BLOCK, [p[2], p[3]])

    def p_expression_statement_1(self, p):
        """ expression_statement : SEMI """
        p[0] = p[1]

    def p_expression_statement_2(self, p):
        """ expression_statement : expression SEMI """
        p[0] = p[1]

    def p_expression_1(self, p):
        """ expression : assignment_expression """
        p[0] = p[1]

    def p_expression_2(self, p):
        """ expression : expression COMMA assignment_expression"""
        p[0] = [p[1], p[3]]

    def p_assignment_expression_1(self, p):
        """ assignment_expression : conditional_expression"""
        p[0] = p[1]

    def p_assignment_expression_2(self, p):
        """ assignment_expression : unary_expression assignment_operator assignment_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

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

    def p_constant_expression(self, p):
        """ constant_expression : conditional_expression """
        p[0] = p[1]

    def p_conditional_expression_1(self, p):
        """ conditional_expression : logical_or_expression """
        p[0] = p[1]

    def p_conditional_expression_2(self, p):
        """ conditional_expression : logical_or_expression QUESTION expression COLON conditional_expression"""
        #p[0] = AstOpNode(p[2], p[1], [p[3], p[4]])
        p[0] = AstIf(p[1], p[3], p[5], ternary=True)

    def p_logical_or_expression_1(self, p):
        """ logical_or_expression : logical_and_expression """
        p[0] = p[1]

    def p_logical_or_expression_2(self, p):
        """ logical_or_expression : logical_or_expression LOG_OR logical_and_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_logical_and_expression_1(self, p):
        """ logical_and_expression : inclusive_or_expression """
        p[0] = p[1]

    def p_logical_and_expression_2(self, p):
        """ logical_and_expression : logical_and_expression LOG_AND inclusive_or_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_inclusive_or_expression_1(self, p):
        """ inclusive_or_expression : exclusive_or_expression """
        p[0] = p[1]

    def p_inclusive_or_expression_2(self, p):
        """ inclusive_or_expression : inclusive_or_expression OR exclusive_or_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_exclusive_or_expression_1(self, p):
        """ exclusive_or_expression : and_expression """
        p[0] = p[1]

    def p_exclusive_or_expression_2(self, p):
        """ exclusive_or_expression : exclusive_or_expression XOR and_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_and_expression_1(self, p):
        """ and_expression : equality_expression """
        p[0] = p[1]

    def p_and_expression_2(self, p):
        """ and_expression : and_expression AMP equality_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_equality_expression_1(self, p):
        """ equality_expression : relational_expression """
        p[0] = p[1]

    def p_equality_expression_2(self, p):
        """ equality_expression : equality_expression EQ_EQ relational_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_equality_expression_3(self, p):
        """ equality_expression : equality_expression EQ_NE relational_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_1(self, p):
        """ relational_expression : shift_expression"""
        p[0] = p[1]

    def p_relational_expression_2(self, p):
        """ relational_expression : relational_expression LT shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_3(self, p):
        """ relational_expression : relational_expression GT shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_4(self, p):
        """ relational_expression : relational_expression LE shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_5(self, p):
        """ relational_expression : relational_expression GE shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_shift_expression_1(self, p):
        """ shift_expression : additive_expression """
        p[0] = p[1]

    def p_shift_expression_2(self, p):
        """ shift_expression : shift_expression SH_LEFT additive_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_shift_expression_3(self, p):
        """ shift_expression : shift_expression SH_RIGHT additive_expression """
        p[0] = AstOpNode(p[2], p[1], p[3])

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

    def p_cast_expression_1(self, p):
        """ cast_expression : unary_expression"""
        p[0] = p[1]

    def p_cast_expression_2(self, p):
        """ cast_expression : ROUND_OPEN type_name ROUND_CLOSE cast_expression"""
        # FIXME Cast op
        p[0] = AstOpNode("cast", p[2], p[4])

    def p_type_name_1(self, p):
        """ type_name : specifier_qualifier_list """
        p[0] = p[1]

    def p_type_name_2(self, p):
        """ type_name : specifier_qualifier_list abstract_declarator"""
        p[0] = p[1]

    def p_specifier_qualifier_list_1(self, p):
        """ specifier_qualifier_list : type_specifier specifier_qualifier_list"""
        p[0] = AstNode(AstType.TYPE_LIST, [p[1], p[2]])

    def p_specifier_qualifier_list_2(self, p):
        """ specifier_qualifier_list : type_specifier"""
        p[0] = p[1]

    def p_specifier_qualifier_list_3(self, p):
        """ specifier_qualifier_list : type_qualifier specifier_qualifier_list"""
        p[0] = AstNode(AstType.TYPE_LIST, [p[1], p[2]])

    def p_specifier_qualifier_list_4(self, p):
        """ specifier_qualifier_list : type_qualifier"""
        p[0] = p[1]

    def p_unary_expression_1(self, p):
        """ unary_expression : postfix_expression """
        p[0] = p[1]

    def p_unary_expression_2(self, p):
        """ unary_expression : PLUSPLUS unary_expression """
        p[0] = [p[1], p[2]]

    def p_unary_expression_3(self, p):
        """ unary_expression : MINUSMINUS unary_expression """
        p[0] = [p[1], p[2]]

    def p_unary_expression_4(self, p):
        """ unary_expression : unary_operator cast_expression """
        p[0] = [p[1], p[2]]

    def p_unary_operator(self, p):
        """ unary_operator : AMP
                           | STAR
                           | PLUS
                           | MINUS
                           | TILDE
                           | NOT """
        p[0] = AstNode(AstType.UNARY, p[1])

    def p_argument_expression_list_1(self, p):
        """ argument_expression_list : assignment_expression"""
        p[0] = p[1]

    def p_argument_expression_list_2(self, p):
        """ argument_expression_list : argument_expression_list COMMA assignment_expression"""
        p[0] = [p[1], p[3]]

    def p_postfix_expression_1(self, p):
        """ postfix_expression : primary_expression """
        p[0] = p[1]

    def p_postfix_expression_2(self, p):
        """ postfix_expression : postfix_expression SQUARE_OPEN expression SQUARE_CLOSE """
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_postfix_expression_3(self, p):
        """ postfix_expression : postfix_expression ROUND_OPEN ROUND_CLOSE """
        p[0] = [p[1], p[2], p[3]]

    def p_postfix_expression_4(self, p):
        """ postfix_expression : postfix_expression ROUND_OPEN argument_expression_list ROUND_CLOSE """
        p[0] = [p[1], p[2], p[3], p[4]]

    def p_postfix_expression_5(self, p):
        """ postfix_expression : postfix_expression DOT IDENTIFIER"""
        p[0] = [p[1], p[2], p[3]]

    def p_postfix_expression_6(self, p):
        """ postfix_expression : postfix_expression PTR_OP IDENTIFIER"""
        p[0] = [p[1], p[2], p[3]]

    def p_postfix_expression_7(self, p):
        """ postfix_expression : postfix_expression PLUSPLUS"""
        p[0] = [p[1], p[2]]

    def p_postfix_expression_8(self, p):
        """ postfix_expression : postfix_expression MINUSMINUS"""
        p[0] = [p[1], p[2]]

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

    def p_primary_expression_5(self, p):
        """ primary_expression : ROUND_OPEN expression ROUND_CLOSE """
        p[0] = [p[1], p[2], p[3]]
