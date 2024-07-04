from sic.token import TokenType, Token
from sic.scan import Scan
from sic.ast import (
    AstType,
    AstNode,
    AstOpNode,
    AstPointer,
    AstIf,
    AstLoop,
    AstStruct,
    AstEnum,
    AstGoto,
    AstLabel,
    AstPrePostOp,
    AstCast,
)

from ply import yacc
from enum import Enum

class Types(Enum):
    TYPE = 1
    IDENTIFIER = 2

class Parser:
    def __init__(self, scanner, debug=False):
        self.tokens = scanner.tokens
        self.scanner = scanner
        self.yacc = yacc.yacc(module=self, start="translation_unit")
        self.debug = debug
        self.error = False
        self.scopes = [dict()]
        self.is_typedef = False

    def success(self):
        return self.scanner.success and not self.error

    def readfile(self, fname):
        with open(fname, "r") as fd:
            return fd.read()

    def scope_new(self):
        self.scopes.append(dict())

    def scope_pop(self):
        self.scopes.pop()

    def define_type(self, typename):
        self.scanner.add_type(typename)
        pt = self.scopes[-1].get(typename, None)
        if pt is not None:
            raise ValueError("Variable or type already defined: {}".format(varname))
        self.scopes[-1][typename] = Types.TYPE

    def define_variable(self, varname):
        pt = self.scopes[-1].get(varname, None)
        if pt is not None:
            raise ValueError("Variable or type already defined: {}".format(varname))
        self.scopes[-1][varname] = Types.VARIABLE

    def parse(self, filename, data=None):
        self.scanner.fname = filename
        if data is None and filename:
            data = self.readfile(filename)
        return self.yacc.parse(input=data, lexer=self.scanner.lexer, debug=self.debug)

    def make_list(self, *items):
        """
        >>> s = Scan()
        >>> p = Parser(s)
        >>> p.make_list(4)
        [4]
        >>> p.make_list(4, 8)
        [4, 8]
        >>> p.make_list({"a": 4, "b": 5}, 8)
        [{'a': 4, 'b': 5}, 8]
        >>> p.make_list({"a": 4, "b": 5}, {"c": 8})
        [{'a': 4, 'b': 5}, {'c': 8}]
        """
        if not items:
            return []
        # print("LL0", type(items))
        if type(items) == tuple:
            items = list(items)
        if type(items) != list:
            return [items]

        # print("LL1", items)
        if type(items[0]) == list:
            #base = [items[0]]
            base = items[0]
        else:
            base = [items[0]]

        for i in items[1:]:
            if type(i) == list:
                base += i
            else:
                base.append(i)
        # print("LL2", base)
        return base

    def p_empty(self, p):
        """empty :"""
        p[0] = None

    def p_error(self, p):
        print("Parser ERROR: '%s'" % p)
        self.error = True

    def p_translation_unit_1(self, p):
        """ translation_unit : external_declaration """
        p[0] = AstNode(AstType.ROOT, p[1])

    def p_translation_unit_2(self, p):
        """ translation_unit : translation_unit external_declaration """
        p[0] = AstNode(AstType.ROOT, [p[1], p[2]])

    #def p_external_declarations_1(self, p):
    #    """external_declarations : external_declaration"""
    #    p[0] = p[1]

    #def p_external_declarations_2(self, p):
    #    """external_declarations : external_declarations external_declaration"""
    #    p[0] = [p[1], p[2]]

    def p_external_declaration_1(self, p):
        """external_declaration : function_definition"""
        p[0] = p[1]

    def p_external_declaration_2(self, p):
        """external_declaration : declaration"""
        p[0] = p[1]

    def p_external_declaration_3(self, p):
        """external_declaration : statement_list"""
        p[0] = p[1]

    def p_function_definition_1(self, p):
        """function_definition : declaration_specifiers declarator declaration_list compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3], p[4]])

    def p_function_definition_2(self, p):
        """function_definition : declaration_specifiers declarator compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3]])

    def p_function_definition_3(self, p):
        """function_definition : declarator declaration_list compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2], p[3]])

    def p_function_definition_4(self, p):
        """function_definition : declarator compound_statement"""
        p[0] = AstNode(AstType.FUNCDEF, [p[1], p[2]])

    def has_typedef(self, ast):
        if not ast:
            return False

        lst = []
        if type(ast) == list:
            lst = ast
        elif isinstance(ast, AstNode):
            if ast.nodetype == AstType.TYPE_STORAGE and ast.value == "typedef":
                return True
            else:
                lst = ast.value
                if isinstance(lst, AstNode):
                    lst = [lst.value]
        else:
            return None

        for ch in lst:
            if isinstance(ch, AstNode):
                if self.has_typedef(ch):
                    return True

        return False

    def resolve_value(self, ast):
        if not ast:
            return None

        #print("AST", ast)
        lst = []
        if type(ast) == list:
            lst = ast
        elif isinstance(ast, AstNode):
            if ast.nodetype == AstType.IDENTIFIER:
                return ast.value
            else:
                lst = ast.value
        else:
            return None

        for ch in lst:
            if isinstance(ch, AstNode):
                tmp = self.resolve_value(ch)
                if tmp is not None:
                    return tmp

        return None

    def p_declaration_1(self, p):
        """declaration : declaration_specifiers SEMI"""
        p[0] = p[1]

    def p_declaration_2(self, p):
        """declaration : declaration_specifiers init_declarator_list SEMI"""
        #print("DECLA1", p[1])
        #print("DECLA2", p[2])
        ht = self.has_typedef(p[1])
        if ht:
            val = self.resolve_value(p[2])
            if val is not None:
                print("DECLARE", val, p[1])
                self.scanner.add_type(val)
        p[0] = self.make_list(p[1], p[2])

    def p_declaration_specifiers_1(self, p):
        """declaration_specifiers : storage_class_specifier"""
        p[0] = p[1]

    def p_declaration_specifiers_2(self, p):
        """declaration_specifiers : storage_class_specifier declaration_specifiers"""
        #p[0] = self.make_list(p[1], p[2])
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_3(self, p):
        """declaration_specifiers : type_specifier"""
        p[0] = p[1]

    def p_declaration_specifiers_4(self, p):
        """declaration_specifiers : type_specifier declaration_specifiers"""
        #p[0] = self.make_list(p[1], p[2])
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_5(self, p):
        """declaration_specifiers : type_qualifier"""
        p[0] = p[1]

    def p_declaration_specifiers_6(self, p):
        """declaration_specifiers : type_qualifier declaration_specifiers"""
        #p[0] = self.make_list(p[1], p[2])
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_7(self, p):
        """declaration_specifiers : function_specifier"""
        p[0] = p[1]

    def p_declaration_specifiers_8(self, p):
        """declaration_specifiers : function_specifier declaration_specifiers"""
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_9(self, p):
        """declaration_specifiers : alignment_specifier"""
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_10(self, p):
        """declaration_specifiers : alignment_specifier declaration_specifiers"""
        p[0] = [p[1], p[2]]

    def p_alignment_specifier(self, p):
        """alignment_specifier : _Alignas ROUND_OPEN type_name ROUND_CLOSE
                               | _Alignas ROUND_OPEN constant_expression ROUND_CLOSE"""
        p[0] = AstNode(AstType.ALIGN_AS, p[3])

    def p_function_specifier(self, p):
        """ function_specifier : INLINE """
        p[0] = p[1]

    def p_storage_class_specifier(self, p):
        """
        storage_class_specifier : TYPEDEF
                                | EXTERN
                                | STATIC
                                | AUTO
                                | REGISTER"""
        if p[1] == "typedef":
            self.is_typedef = True
        p[0] = AstNode(AstType.TYPE_STORAGE, p[1])

    def p_type_specifier_no_type_name(self, p):
        """
        type_specifier_no_typename : VOID
                                   | CHAR
                                   | SHORT
                                   | INT
                                   | LONG
                                   | FLOAT
                                   | DOUBLE
                                   | SIGNED
                                   | UNSIGNED
                                   | _Bool
                                   | _Complex"""
        p[0] = AstNode(AstType.TYPE, p[1])

    def p_type_specifier(self, p):
        """
        type_specifier : typedef_name
                       | struct_or_union_specifier
                       | type_specifier_no_typename
                       | enum_specifier
                       | atomic_specifier"""
        p[0] = AstNode(AstType.TYPE, p[1])

    def p_typedef_name(self, p):
        """ typedef_name : TYPE_NAME"""
        p[0] = AstNode(AstType.TYPE, p[1])

    def p_atomic_specifier(self, p):
        """ atomic_specifier : _Atomic ROUND_OPEN type_name ROUND_CLOSE"""
        p[0] = AstNode(AstType.ATOMIC, p[3])

    def p_enum_specifier_1(self, p):
        """enum_specifier : ENUM CURLY_OPEN enumerator_list CURLY_CLOSE"""
        p[0] = AstEnum(None, p[3])

    def p_enum_specifier_2(self, p):
        """enum_specifier : ENUM identifier_or_type_name CURLY_OPEN enumerator_list CURLY_CLOSE"""
        p[0] = AstEnum(p[1], p[4])

    def p_enum_specifier_3(self, p):
        """enum_specifier : ENUM identifier_or_type_name"""
        p[0] = AstEnum(p[1], None)

    def p_enumerator_list_1(self, p):
        """enumerator_list : enumerator"""
        p[0] = p[1]

    def p_enumerator_list_2(self, p):
        """enumerator_list : enumerator_list COMMA enumerator"""
        #p[0] = self.make_list(p[1], p[3])
        p[0] = [p[1], p[3]]

    def p_enumerator_1(self, p):
        """enumerator : IDENTIFIER"""
        p[0] = p[1]

    def p_enumerator_2(self, p):
        """enumerator : IDENTIFIER EQ constant_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_struct_or_union_specifier_1(self, p):
        """struct_or_union_specifier : struct_or_union identifier_or_type_name struct_declaration_list CURLY_CLOSE"""
        p[0] = AstStruct(p[1], p[2], p[4])

    def p_struct_or_union_specifier_2(self, p):
        """struct_or_union_specifier : struct_or_union CURLY_OPEN struct_declaration_list CURLY_CLOSE"""
        p[0] = AstStruct(p[1], None, p[3])

    def p_struct_or_union_specifier_3(self, p):
        """struct_or_union_specifier : struct_or_union identifier_or_type_name"""
        p[0] = AstStruct(p[1], p[2], None)

    def p_struct_or_union_1(self, p):
        """struct_or_union : STRUCT"""
        p[0] = AstNode(AstType.STRUCT, p[1])

    def p_struct_or_union_2(self, p):
        """struct_or_union : UNION"""
        p[0] = AstNode(AstType.UNION, p[1])

    def p_struct_declaration_list_1(self, p):
        """struct_declaration_list : struct_declaration"""
        p[0] = p[1]

    def p_struct_declaration_list_2(self, p):
        """struct_declaration_list : struct_declaration struct_declaration_list"""
        #p[0] = self.make_list(p[1], p[2])
        p[0] = [p[1], p[2]]
        """
        if type(p[1]) == list:
            p[0] = p[1][:]
            p[0].append(p[2])
        else:
            p[0] = [p[1], p[2]]
        """

    def p_struct_declaration(self, p):
        """struct_declaration : specifier_qualifier_list struct_declarator_list SEMI"""
        #p[0] = self.make_list(p[1], p[2])
        p[0] = [p[1], p[2]]

    def p_struct_declarator_list_1(self, p):
        """struct_declarator_list : struct_declarator"""
        p[0] = p[1]

    def p_struct_declarator_list_2(self, p):
        """struct_declarator_list : struct_declarator_list COMMA struct_declarator"""
        p[0] = self.make_list(p[1], p[3])
        #p[0] = [p[1], p[3]]

    def p_struct_declarator_1(self, p):
        """struct_declarator : declarator"""
        p[0] = p[1]

    def p_struct_declarator_2(self, p):
        """struct_declarator : COLON constant_expression"""
        p[0] = self.make_list(p[1], p[2])

    def p_struct_declarator_3(self, p):
        """struct_declarator : declarator COLON constant_expression"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_init_declarator_list_1(self, p):
        """init_declarator_list : init_declarator"""
        p[0] = p[1]

    def p_init_declarator_list_2(self, p):
        """init_declarator_list : init_declarator_list COMMA init_declarator"""
        p[0] = self.make_list(p[1], p[3])

    def p_init_declarator_1(self, p):
        """init_declarator : declarator"""
        p[0] = p[1]

    def p_init_declarator_2(self, p):
        """init_declarator : declarator EQ initializer"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_declarator_1(self, p):
        """declarator : pointer direct_declarator"""
        p[0] = self.make_list(p[1], p[2])

    def p_declarator_2(self, p):
        """declarator : direct_declarator"""
        p[0] = p[1]

    def p_pointer_1(self, p):
        """pointer : STAR"""
        p[0] = AstPointer(None)

    def p_pointer_2(self, p):
        """pointer : STAR type_qualifier_list"""
        p[0] = AstPointer(p[2])

    def p_pointer_3(self, p):
        """pointer : STAR pointer"""
        if type(p[2]) != AstPointer:
            raise ValueError("Invalid pointer")
        p[2].lvl += 1
        p[0] = p[2]

    def p_pointer_4(self, p):
        """pointer : STAR type_qualifier_list pointer"""
        p[0] = AstPointer([p[2], p[3]])

    def p_type_qualifier_list_1(self, p):
        """type_qualifier_list : type_qualifier"""
        p[0] = p[1]

    def p_type_qualifier_list_2(self, p):
        """type_qualifier_list : type_qualifier_list type_qualifier"""
        p[0] = self.make_list(p[1], p[2])

    def p_type_qualifier(self, p):
        """
        type_qualifier : CONST
                       | RESTRICT
                       | VOLATILE
                       | _Atomic"""
        p[0] = AstNode(AstType.TYPE_QUAL, p[1])

    def p_parameter_type_list_1(self, p):
        """parameter_type_list : parameter_list"""
        p[0] = self.make_list(p[1])

    def p_parameter_type_list_2(self, p):
        """parameter_type_list : parameter_list COMMA ELLIPSIS"""
        p[0] = self.make_list(p[1], p[3])

    def p_parameter_list_1(self, p):
        """parameter_list : parameter_declaration"""
        # p[0] = self.make_list(p[1])
        p[0] = [p[1]]

    def p_parameter_list_2(self, p):
        """parameter_list : parameter_list COMMA parameter_declaration"""
        p[0] = self.make_list(p[1], [p[3]])
        # p[0] = [p[1], p[3]]

    def p_parameter_declaration_1(self, p):
        """parameter_declaration : declaration_specifiers declarator"""
        spec = p[1]
        p[0] = self.make_list(p[1], p[2])

    def p_parameter_declaration_2(self, p):
        """parameter_declaration : declaration_specifiers abstract_declarator"""
        p[0] = self.make_list(p[1], p[2])

    def p_parameter_declaration_3(self, p):
        """parameter_declaration : declaration_specifiers"""
        p[0] = p[1]

    def p_abstract_declarator_1(self, p):
        """abstract_declarator : pointer"""
        p[0] = p[1]

    def p_abstract_declarator_2(self, p):
        """abstract_declarator : direct_abstract_declarator"""
        p[0] = p[1]

    def p_abstract_declarator_3(self, p):
        """abstract_declarator : pointer direct_abstract_declarator"""
        p[0] = self.make_list(p[1], p[2])


    def p_direct_abstract_declarator_1(self, p):
        """direct_abstract_declarator : ROUND_OPEN abstract_declarator ROUND_CLOSE"""
        #p[0] = self.make_list(p[1], p[2], p[3])
        p[0] = p[2]

    def p_direct_abstract_declarator_square_1(self, p):
        """direct_abstract_declarator : SQUARE_OPEN SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2])

    def p_direct_abstract_declarator_square_2(self, p):
        """direct_abstract_declarator : SQUARE_OPEN type_qualifier_list SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_abstract_declarator_square_3(self, p):
        """direct_abstract_declarator : SQUARE_OPEN assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_abstract_declarator_square_4(self, p):
        """direct_abstract_declarator : SQUARE_OPEN type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_abstract_declarator_square_5(self, p):
        """direct_abstract_declarator : SQUARE_OPEN STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_abstract_declarator_square_6(self, p):
        """direct_abstract_declarator : SQUARE_OPEN STATIC type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_abstract_declarator_square_7(self, p):
        """direct_abstract_declarator : SQUARE_OPEN type_qualifier_list STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])


    def p_direct_abstract_declarator_square_o1(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_abstract_declarator_square_o2(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN type_qualifier_list SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_abstract_declarator_square_o3(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[4])

    def p_direct_abstract_declarator_square_o4(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_abstract_declarator_square_o5(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_abstract_declarator_square_o6(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN STATIC type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])

    def p_direct_abstract_declarator_square_o7(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN type_qualifier_list STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])

    def p_direct_abstract_declarator_square_p1(self, p):
        """direct_abstract_declarator : SQUARE_OPEN STAR SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])

    def p_direct_abstract_declarator_square_p2(self, p):
        """direct_abstract_declarator : direct_abstract_declarator SQUARE_OPEN STAR SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])


    def p_direct_abstract_declarator_round_1(self, p):
        """direct_abstract_declarator : ROUND_OPEN ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2])

    def p_direct_abstract_declarator_round_2(self, p):
        """direct_abstract_declarator : ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_abstract_declarator_round_3(self, p):
        """direct_abstract_declarator : ROUND_OPEN identifier_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_abstract_declarator_round_4(self, p):
        """direct_abstract_declarator : direct_abstract_declarator ROUND_OPEN ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_abstract_declarator_round_5(self, p):
        """direct_abstract_declarator : direct_abstract_declarator ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_abstract_declarator_round_6(self, p):
        """direct_abstract_declarator : direct_abstract_declarator ROUND_OPEN identifier_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])



    def p_direct_declarator_1(self, p):
        """direct_declarator : IDENTIFIER"""
        p[0] = AstNode(AstType.IDENTIFIER, p[1])

    def p_direct_declarator_1_type(self, p):
        """direct_declarator : TYPE_NAME"""
        p[0] = AstNode(AstType.TYPE, p[1])

    def p_direct_declarator_2(self, p):
        """direct_declarator : ROUND_OPEN declarator ROUND_CLOSE"""
        p[0] = self.make_list(p[2])

    def p_direct_declarator_3_1(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_declarator_3_2(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN type_qualifier_list SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_declarator_3_3(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_declarator_3_4(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN STATIC type_qualifier_list assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])

    def p_direct_declarator_3_5(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_declarator_3_6(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN type_qualifier_list STATIC assignment_expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5], p[6])

    def p_direct_declarator_3_7(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN type_qualifier_list STAR SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4], p[5])

    def p_direct_declarator_3_8(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN STAR SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_declarator_4(self, p):
        """direct_declarator : direct_declarator SQUARE_OPEN SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_direct_declarator_5(self, p):
        """direct_declarator : direct_declarator ROUND_OPEN parameter_type_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_declarator_6(self, p):
        """direct_declarator : direct_declarator ROUND_OPEN identifier_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_direct_declarator_7(self, p):
        """direct_declarator : direct_declarator ROUND_OPEN ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_identifier(self, p):
        """identifier : IDENTIFIER"""
        p[0] = p[1]

    def p_identifier_or_type_name(self, p):
        """identifier_or_type_name : IDENTIFIER
                                   | TYPE_NAME"""
        p[0] = p[1]

    def p_identifier_list_1(self, p):
        """identifier_list : identifier"""
        p[0] = [p[1]]

    def p_identifier_list_2(self, p):
        """identifier_list : identifier_list COMMA IDENTIFIER"""
        p[0] = self.make_list(p[1], p[2])

    def p_initializer_1(self, p):
        """initializer : assignment_expression"""
        p[0] = p[1]

    def p_initializer_2(self, p):
        """initializer : CURLY_OPEN initializer_list CURLY_CLOSE"""
        p[0] = AstNode(AstType.INITIALIZER, p[2])

    def p_initializer_3(self, p):
        """initializer : CURLY_OPEN initializer_list COMMA CURLY_CLOSE"""
        p[0] = AstNode(AstType.INITIALIZER, p[2])

    def p_statement_list_1(self, p):
        """statement_list : statement"""
        p[0] = self.make_list(p[1])

    def p_statement_list_2(self, p):
        """statement_list : statement_list statement"""
        p[0] = self.make_list(p[1], p[2])

    def p_declaration_list_1(self, p):
        """declaration_list : declaration"""
        p[0] = self.make_list(p[1])

    def p_declaration_list_2(self, p):
        """declaration_list : declaration_list declaration"""
        p[0] = self.make_list(p[1], p[2])

    def p_statement_1(self, p):
        """statement : labeled_statement"""
        p[0] = p[1]

    def p_statement_2(self, p):
        """statement : compound_statement"""
        p[0] = p[1]

    def p_statement_3(self, p):
        """statement : expression_statement"""
        p[0] = p[1]

    def p_statement_4(self, p):
        """statement : selection_statement"""
        p[0] = p[1]

    def p_statement_5(self, p):
        """statement : iteration_statement"""
        p[0] = p[1]

    def p_statement_6(self, p):
        """statement : jump_statement"""
        p[0] = p[1]

    def p_labeled_statement_1(self, p):
        """labeled_statement : IDENTIFIER COLON statement"""
        p[0] = AstLabel(p[1], p[3])

    def p_labeled_statement_2(self, p):
        """labeled_statement : CASE IDENTIFIER COLON statement"""
        p[0] = AstLabel(p[2], p[4], case=True)

    def p_labeled_statement_3(self, p):
        """labeled_statement : DEFAULT COLON statement"""
        p[0] = AstLabel("default", p[3], case=True)

    def p_iteration_statement_1(self, p):
        """iteration_statement : WHILE ROUND_OPEN expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.WHILE, p[3], p[5])

    def p_iteration_statement_2(self, p):
        """iteration_statement : DO statement WHILE ROUND_OPEN expression ROUND_CLOSE SEMI"""
        p[0] = AstLoop(AstType.DO, p[5], p[2])

    def p_iteration_statement_3(self, p):
        """iteration_statement : FOR ROUND_OPEN expression SEMI expression SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, p[5], p[9], p[3], p[7])

    def p_iteration_statement_4(self, p):
        """iteration_statement : FOR ROUND_OPEN SEMI expression SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, p[4], p[8], None, p[6])

    def p_iteration_statement_5(self, p):
        """iteration_statement : FOR ROUND_OPEN SEMI SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, None, p[7], None, p[5])

    def p_iteration_statement_6(self, p):
        """iteration_statement : FOR ROUND_OPEN expression SEMI SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, None, p[8], p[3], p[6])

    def p_iteration_statement_7(self, p):
        """iteration_statement : FOR ROUND_OPEN expression SEMI expression SEMI ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, p[5], p[8], p[3])

    def p_iteration_statement_8(self, p):
        """iteration_statement : FOR ROUND_OPEN declaration expression SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, p[4], p[8], p[3], p[6])

    def p_iteration_statement_9(self, p):
        """iteration_statement : FOR ROUND_OPEN declaration expression SEMI ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, p[4], p[7], p[3])

    def p_iteration_statement_10(self, p):
        """iteration_statement : FOR ROUND_OPEN declaration SEMI expression ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, [], p[7], p[3], p[5])

    def p_iteration_statement_11(self, p):
        """iteration_statement : FOR ROUND_OPEN declaration SEMI ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, [], p[6], p[3])

    def p_iteration_statement_12(self, p):
        """iteration_statement : FOR ROUND_OPEN SEMI SEMI ROUND_CLOSE statement"""
        p[0] = AstLoop(AstType.FOR, [], p[6])

    def p_selection_statement_1(self, p):
        """selection_statement : IF ROUND_OPEN expression ROUND_CLOSE statement"""
        p[0] = AstIf(p[3], p[5])

    def p_selection_statement_2(self, p):
        """selection_statement : IF ROUND_OPEN expression ROUND_CLOSE statement ELSE statement"""
        p[0] = AstIf(p[3], p[5], p[7])

    def p_jump_statement_1(self, p):
        """jump_statement : GOTO IDENTIFIER SEMI"""
        p[0] = AstGoto(AstType.GOTO, p[2])

    def p_jump_statement_2(self, p):
        """jump_statement : CONTINUE SEMI"""
        p[0] = AstGoto(AstType.CONTINUE, None)

    def p_jump_statement_3(self, p):
        """jump_statement : BREAK SEMI"""
        p[0] = AstGoto(AstType.BREAK, None)

    def p_jump_statement_4(self, p):
        """jump_statement : RETURN SEMI"""
        p[0] = AstNode(AstType.KEYWORD, p[1])

    def p_jump_statement_5(self, p):
        """jump_statement : RETURN expression SEMI"""
        p[0] = AstNode(AstType.KEYWORD, [p[1], p[2]])

    def p_compound_statement_1(self, p):
        """compound_statement : CURLY_OPEN CURLY_CLOSE"""
        p[0] = AstNode(AstType.BLOCK, [])

    def p_compound_statement_2(self, p):
        """compound_statement : CURLY_OPEN block_item_list CURLY_CLOSE"""
        p[0] = AstNode(AstType.BLOCK, p[2])

    #def p_compound_statement_2(self, p):
    #    """compound_statement : CURLY_OPEN statement_list CURLY_CLOSE"""
    #    p[0] = AstNode(AstType.BLOCK, p[2])

    #def p_compound_statement_3(self, p):
    #    """compound_statement : CURLY_OPEN declaration_list CURLY_CLOSE"""
    #    p[0] = AstNode(AstType.BLOCK, p[2])

    #def p_compound_statement_4(self, p):
    #    """compound_statement : CURLY_OPEN declaration_statement_list CURLY_CLOSE"""
    #    p[0] = AstNode(AstType.BLOCK, p[2])

    def p_block_item_list_1(self, p):
        """ block_item_list : block_item"""
        p[0] = p[1]

    def p_block_item_list_2(self, p):
        """ block_item_list : block_item_list block_item"""
        p[0] = [p[1], p[2]]

    def p_block_item_1(self, p):
        """ block_item : declaration"""
        p[0] = p[1]

    def p_block_item_2(self, p):
        """ block_item : statement"""
        p[0] = p[1]

    def p_declaration_statement_list_1(self, p):
        """declaration_statement_list : declaration_list"""
        p[0] = p[1]

    def p_declaration_statement_list_2(self, p):
        """declaration_statement_list : statement_list"""
        p[0] = p[1]

    def p_declaration_statement_list_3(self, p):
        """declaration_statement_list : declaration_statement_list declaration_list"""
        p[0] = self.make_list(p[1], p[2])

    def p_declaration_statement_list_4(self, p):
        """declaration_statement_list : declaration_statement_list statement_list"""
        p[0] = self.make_list(p[1], p[2])

    def p_expression_statement_1(self, p):
        """expression_statement : SEMI"""
        p[0] = []
        self.is_typedef = False

    def p_expression_statement_2(self, p):
        """expression_statement : expression SEMI"""
        p[0] = p[1]

    def p_expression_1(self, p):
        """expression : assignment_expression"""
        p[0] = p[1]

    def p_expression_2(self, p):
        """expression : expression COMMA assignment_expression"""
        p[0] = self.make_list(p[1], p[2])

    def p_assignment_expression_1(self, p):
        """assignment_expression : conditional_expression"""
        p[0] = p[1]

    def p_assignment_expression_2(self, p):
        """assignment_expression : unary_expression assignment_operator assignment_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_assignment_expression_3(self, p):
        """assignment_expression : ROUND_OPEN compound_statement_list ROUND_CLOSE"""
        p[0] = p[2]

    def p_compound_statement_list_1(self, p):
        """compound_statement_list : compound_statement"""
        p[0] = p[1]

    def p_compound_statement_list_2(self, p):
        """compound_statement_list : compound_statement_list COMMA compound_statement"""
        if type(p[1]) != list:
            p[1] = [p[1]]
        if type(p[3]) == list:
            p[1] += p[3]
        else:
            p[1] = [p[1], p[3]]
        p[0] = p[1]

    def p_assignment_operator(self, p):
        """
        assignment_operator : EQ
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
        """constant_expression : conditional_expression"""
        p[0] = p[1]

    def p_conditional_expression_1(self, p):
        """conditional_expression : logical_or_expression"""
        p[0] = p[1]

    def p_conditional_expression_2(self, p):
        """conditional_expression : logical_or_expression QUESTION expression COLON conditional_expression"""
        p[0] = AstIf(p[1], p[3], p[5], ternary=True)

    def p_logical_or_expression_1(self, p):
        """logical_or_expression : logical_and_expression"""
        p[0] = p[1]

    def p_logical_or_expression_2(self, p):
        """logical_or_expression : logical_or_expression LOG_OR logical_and_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_logical_and_expression_1(self, p):
        """logical_and_expression : inclusive_or_expression"""
        p[0] = p[1]

    def p_logical_and_expression_2(self, p):
        """logical_and_expression : logical_and_expression LOG_AND inclusive_or_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_inclusive_or_expression_1(self, p):
        """inclusive_or_expression : exclusive_or_expression"""
        p[0] = p[1]

    def p_inclusive_or_expression_2(self, p):
        """inclusive_or_expression : inclusive_or_expression OR exclusive_or_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_exclusive_or_expression_1(self, p):
        """exclusive_or_expression : and_expression"""
        p[0] = p[1]

    def p_exclusive_or_expression_2(self, p):
        """exclusive_or_expression : exclusive_or_expression XOR and_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_and_expression_1(self, p):
        """and_expression : equality_expression"""
        p[0] = p[1]

    def p_and_expression_2(self, p):
        """and_expression : and_expression AMP equality_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_equality_expression_1(self, p):
        """equality_expression : relational_expression"""
        p[0] = p[1]

    def p_equality_expression_2(self, p):
        """equality_expression : equality_expression EQ_EQ relational_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_equality_expression_3(self, p):
        """equality_expression : equality_expression EQ_NE relational_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_1(self, p):
        """relational_expression : shift_expression"""
        p[0] = p[1]

    def p_relational_expression_2(self, p):
        """relational_expression : relational_expression LT shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_3(self, p):
        """relational_expression : relational_expression GT shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_4(self, p):
        """relational_expression : relational_expression LE shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_relational_expression_5(self, p):
        """relational_expression : relational_expression GE shift_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_shift_expression_1(self, p):
        """shift_expression : additive_expression"""
        p[0] = p[1]

    def p_shift_expression_2(self, p):
        """shift_expression : shift_expression SH_LEFT additive_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_shift_expression_3(self, p):
        """shift_expression : shift_expression SH_RIGHT additive_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_additive_expression_1(self, p):
        """additive_expression : multiplicative_expression"""
        p[0] = p[1]

    def p_additive_expression_2(self, p):
        """additive_expression : additive_expression PLUS multiplicative_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_additive_expression_3(self, p):
        """additive_expression : additive_expression MINUS multiplicative_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_1(self, p):
        """multiplicative_expression : cast_expression"""
        p[0] = p[1]

    def p_multiplicative_expression_2(self, p):
        """multiplicative_expression : multiplicative_expression STAR cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_3(self, p):
        """multiplicative_expression : multiplicative_expression SLASH cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_multiplicative_expression_4(self, p):
        """multiplicative_expression : multiplicative_expression MOD cast_expression"""
        p[0] = AstOpNode(p[2], p[1], p[3])

    def p_cast_expression_1(self, p):
        """cast_expression : unary_expression"""
        p[0] = p[1]

    def p_cast_expression_2(self, p):
        """cast_expression : ROUND_OPEN type_name ROUND_CLOSE cast_expression"""
        p[0] = AstCast(p[2], p[4])

    def p_type_name_1(self, p):
        """type_name : specifier_qualifier_list"""
        p[0] = p[1]

    def p_type_name_2(self, p):
        """type_name : specifier_qualifier_list abstract_declarator"""
        p[0] = p[1]

    def p_specifier_qualifier_list_1(self, p):
        """specifier_qualifier_list : type_specifier specifier_qualifier_list"""
        p[0] = AstNode(AstType.TYPE_LIST, [p[1], p[2]])

    def p_specifier_qualifier_list_2(self, p):
        """specifier_qualifier_list : type_specifier"""
        p[0] = p[1]

    def p_specifier_qualifier_list_3(self, p):
        """specifier_qualifier_list : type_qualifier specifier_qualifier_list"""
        p[0] = AstNode(AstType.TYPE_LIST, [p[1], p[2]])

    def p_specifier_qualifier_list_4(self, p):
        """specifier_qualifier_list : type_qualifier"""
        p[0] = p[1]

    def p_unary_expression_1(self, p):
        """unary_expression : postfix_expression"""
        p[0] = p[1]

    def p_unary_expression_2(self, p):
        """unary_expression : PLUSPLUS unary_expression"""
        p[0] = AstPrePostOp(p[1], p[2], pre=True)

    def p_unary_expression_3(self, p):
        """unary_expression : MINUSMINUS unary_expression"""
        p[0] = AstPrePostOp(p[1], p[2], pre=True)

    def p_unary_expression_4(self, p):
        """unary_expression : unary_operator cast_expression"""
        p[0] = self.make_list(p[1], p[2])

    def p_unary_expression_5(self, p):
        """unary_expression : SIZEOF unary_expression"""
        p[0] = AstNode(AstType.SIZEOF, p[2])

    def p_unary_expression_6(self, p):
        """unary_expression : SIZEOF ROUND_OPEN type_name ROUND_CLOSE"""
        p[0] = AstNode(AstType.SIZEOF, p[3])

    def p_unary_operator(self, p):
        """
        unary_operator : AMP
                       | STAR
                       | PLUS
                       | MINUS
                       | TILDE
                       | NOT"""
        p[0] = AstNode(AstType.UNARY, p[1])

    def p_argument_expression_list_1(self, p):
        """argument_expression_list : assignment_expression"""
        p[0] = p[1]

    def p_argument_expression_list_2(self, p):
        """argument_expression_list : argument_expression_list COMMA assignment_expression"""
        p[0] = self.make_list(p[1], p[3])

    def p_postfix_expression_1(self, p):
        """postfix_expression : primary_expression"""
        p[0] = p[1]

    def p_postfix_expression_2(self, p):
        """postfix_expression : postfix_expression SQUARE_OPEN expression SQUARE_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_postfix_expression_3(self, p):
        """postfix_expression : postfix_expression ROUND_OPEN ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_postfix_expression_4(self, p):
        """postfix_expression : postfix_expression ROUND_OPEN argument_expression_list ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3], p[4])

    def p_postfix_expression_5(self, p):
        """postfix_expression : postfix_expression DOT identifier_or_type_name"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_postfix_expression_6(self, p):
        """postfix_expression : postfix_expression PTR_OP identifier_or_type_name"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_postfix_expression_7(self, p):
        """postfix_expression : postfix_expression PLUSPLUS"""
        p[0] = AstPrePostOp(p[2], p[1], pre=False)

    def p_postfix_expression_8(self, p):
        """postfix_expression : postfix_expression MINUSMINUS"""
        p[0] = AstPrePostOp(p[2], p[1], pre=False)

    def p_postfix_expression_9(self, p):
        """postfix_expression : ROUND_OPEN type_name ROUND_CLOSE CURLY_OPEN initializer_list CURLY_CLOSE"""
        p[0] = self.AstCast(p[2], [p[4], p[5], p[6]])

    def p_postfix_expression_10(self, p):
        """postfix_expression : ROUND_OPEN type_name ROUND_CLOSE CURLY_OPEN initializer_list COMMA CURLY_CLOSE"""
        p[0] = self.AstCast(p[2], [p[4], p[5], p[7]])

    def p_initializer_list_1(self, p):
        """ initializer_list : initializer """
        p[0] = [p[1]]

    def p_initializer_list_2(self, p):
        """ initializer_list : initializer_list COMMA initializer """
        # TODO designation
        p[1].append(p[3])
        p[0] = p[1]

    def p_primary_expression_1(self, p):
        """primary_expression : FRAC_LIT"""
        p[0] = AstNode(AstType.FRAC_LIT, p[1])

    def p_primary_expression_2(self, p):
        """primary_expression : INT_LIT"""
        p[0] = AstNode(AstType.INT_LIT, p[1])

    def p_primary_expression_3(self, p):
        """primary_expression : string_literals"""
        p[0] = AstNode(AstType.STR_LIT, p[1])

    def p_primary_expression_4(self, p):
        """primary_expression : IDENTIFIER"""
        p[0] = AstNode(AstType.IDENTIFIER, p[1])

    def p_primary_expression_5(self, p):
        """primary_expression : ROUND_OPEN expression ROUND_CLOSE"""
        p[0] = self.make_list(p[1], p[2], p[3])

    def p_primary_expression_6(self, p):
        """primary_expression : CONSTANT_CHAR"""
        # TODO Constants
        res = None
        if type(p[1]) == str and len(p[1]) >= 3 and p[1][0] == "'":
            tmp = p[1][1:-1]
            if tmp:
                if len(tmp) == 1:
                    res = ord(tmp)
                elif len(tmp) == 2 and tmp[0] == "\\":
                    if tmp[1] == "n":
                        res = ord("\n")
                    elif tmp[1] == "r":
                        res = ord("\r")
                    elif tmp[1] == "t":
                        res = ord("\t")
                    elif tmp[1] == "0":
                        res = 0
                    elif tmp[1] == "\\":
                        res = ord("\\")
                    elif tmp[1] == "a":
                        res = ord("\a")
                    elif tmp[1] == "b":
                        res = ord("\b")
                    elif tmp[1] == "f":
                        res = ord("\f")
                    elif tmp[1] == "v":
                        res = ord("\v")
                    elif tmp[1] == "'":
                        res = ord("'")
                    elif tmp[1] == '"':
                        res = ord('"')

        if res is None:
            raise ValueError("Invalid char: {}".format(p[1]))
        p[0] = AstNode(AstType.INT_LIT, str(res))

    def handle_escapes(self, s):
        res = ""
        in_escape = False
        for c in s:
            if in_escape:
                if c == "n":
                    res += "\n"
                elif c == "r":
                    res += "\r"
                elif c == "t":
                    res += "\t"
                elif c == "0":
                    res += "\0"
                elif c == "\\":
                    res += "\\"
                elif c == "a":
                    res += "\a"
                elif c == "b":
                    res += "\b"
                elif c == "f":
                    res += "\f"
                elif c == "v":
                    res += "\v"
                elif c == "'":
                    res += "'"
                elif c == '"':
                    res += '"'
                else:
                    res += "\\" + c
                in_escape = False
            elif c == "\\":
                in_escape = True
            else:
                in_escape = False
                res += c
        return res

    def p_string_literals_1(self, p):
        """string_literals : STR_LIT"""
        p[0] = AstNode(AstType.STR_LIT, self.handle_escapes(p[1][1:-1]))

    def p_string_literals_2(self, p):
        """string_literals : string_literals STR_LIT"""
        if (
            type(p[1]) == AstNode
            and p[1].nodetype == AstType.STR_LIT
            and type(p[2]) == str
        ):
            v2 = p[1].value
            if v2 and v2[-1] == '"' and p[2] and p[2][-1] == '"':
                p[1].value = v2[:-1] + p[2][1:]
            else:
                p[1].value += p[2]
            p[0] = p[1]
        else:
            p[0] = AstNode(AstType.STR_LIT, p[1] + p[2])
