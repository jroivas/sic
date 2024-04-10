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
            p[0] = []
        else:
            p[0] = {"ROOT": p[1]}

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
        p[0] = [p[1]]

    def p_declaration_2(self, p):
        """ declaration : declaration_specifiers init_declarator_list SEMI """
        p[0] = [p[1], p[2]]

    def p_declaration_specifiers_1(self, p):
        """ declaration_specifiers : type_specifier """
        p[0] = p[1]

    def p_type_specifier(self, p):
        """ type_specifier : VOID
                           | CHAR
                           | INT
                           | LONG
                           | FLOAT
                           | DOUBLE
                           | SIGNED
                           | UNSIGNED"""
        p[0] = p[1]

    def p_init_declarator_list_1(self, p):
        """ init_declarator_list : init_declarator"""
        p[0] = [p[1]]

    def p_init_declarator_list_2(self, p):
        """ init_declarator_list : init_declarator_list COMMA init_declarator"""
        p[1].extend(p[3])
        p[0] = p[1]

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
        p[0] = [p[1], p[2]]

    def p_expression_statement_2(self, p):
        """ expression_statement : expression_statement expression SEMI """
        #p[1].extend(p[2])
        #p[1].extend(p[3])
        p[0] = [p[1], p[2], p[3]]

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
        p[0] = AstOpNode(p[1], 0, p[2])

    def p_unary_expression_3(self, p):
        """ unary_expression : MINUS cast_expression """
        p[0] = AstOpNode(p[1], 0, p[2])

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


class ParserItem:
    def __init__(self, val):
        self.val = val
        self.reduced = []

    def reduce(self, red):
        self.reduced.append(red)

    def matches(self, val):
        if val == self.val:
            return True
        if type(self.val) == Token and val == self.val.tokentype:
            return True

        if val in self.reduced:
            return True

        return False

    def get(self):
        if self.reduced:
            return self.reduced[-1]
        return self.val

    def __eq__(self, b):
        if type(b) == ParserItem:
            if self.val == b.val:
                return True
            if self.matches(b.get()):
                return True
            return False
        if self.matches(b):
            return True
        return False

    def __repr__(self):
        if self.reduced:
            return "ParserItem({})".format("-".join(self.reduced))
        return "ParserItem({})".format(self.get())

class Node:
    def __init__(self, key):
        self.key = key
        self.child = []

    def add(self, node):
        self.child.add(node)

    def find(self, key):
        if self.key == key:
            return self

        for c in self.child:
            res = c.find(key)
            if res:
                return res

        return None

    def __repr__(self):
        res = "Node({})".format(self.key)
        for c in self.child:
            res += "\n   {}".format(c)
        return res

def NodeTerminal():
    def __init__(self, key):
        self.key = key

    def find(self, key):
        if self.key == key:
            return self
        return None

class Grammar:
    def __init__(self, lang):
        self.lang = lang
        self.terminals = []
        self.keywords = []
        self.kwmap = {}
        self.parselang()

    def add_keyword(self, key):
        if key not in self.keywords:
            self.keywords.append(key)

    def add_terminal(self, term):
        if term not in self.terminals:
            self.terminals.append(term)

    def parselang(self):
        for item in self.lang:
            key = item[0]
            self.add_keyword(key)

            kmap = self.kwmap.get(key, [])
            for cases in item[1]:
                kmap.append(cases[:])
                for case in cases:
                    if type(case) != str:
                        self.add_terminal(case)
            self.kwmap[key] = kmap

    def printcases(self):
        for key in self.keywords:
            print("{}:".format(key))
            for case in self.kwmap.get(key, []):
                print("  case: {}".format(case))

    def __repr__(self):
        return "{} -> {}".format(",".join(self.keywords), ",".join([str(x) for x in self.terminals]))

class oldParser:
    def __init__(self, scan, lang):
        self.scan = scan
        self.ast = {}
        self.language = lang
        self.root = Node("root")

    def build_graph(self):
        for case, rules in self.language.items():
            case_node = self.root.find(case)
            if case_node is None:
                case_node = Node(case)

            for rule in rules:
                for item in rule:
                    if type(item) == str:
                        rule_node = self.root.find(rule_node)
                        if rule_node is None:
                            rule_node = Node(item)
                        case_node.add(rule_node)

    def map_one_item(self, item):
        """
        >>> lang = {"factor" : [(TokenType.INT_LIT,)] }
        >>> p = Parser(None, lang)
        >>> p.map_one_item(Token(0, 0, TokenType.INT_LIT, 5))
        'factor'
        >>> p.map_one_item(TokenType.INT_LIT)
        'factor'
        >>> p.map_one_item(TokenType.STR_LIT)
        """
        for case, rules in self.language.items():
            for rule in rules:
                if len(rule) != 1:
                    continue
                if rule[0] == item:
                    return case
                if type(item) == Token and rule[0] == item.tokentype:
                    return case
        return None

    def map_list_item(self, item):
        if item is None:
            return None

        if type(item) != tuple:
            item = tuple(item)
        litem = len(item)

        for case, rules in self.language.items():
            for rule in rules:
                if len(rule) > litem:
                    continue

                err = False
                lr = len(rule)
                df = litem - lr
                for pos in range(0, df + 1):
                    print("MM", pos, rule, item[pos:pos+lr])
                    for a,b in zip(rule, item[pos:pos+lr]):
                        if a == b:
                            continue
                        if b == a:
                            continue
                        err = True
                    if not err:
                        return case
                """
                if len(rule) != litem:
                    continue

                err = False
                for a,b in zip(rule, item):
                    if a == b:
                        continue
                    #if self.can_reduce(b, a):
                    if type(b) == ParserItem and b.matches(a):
                        continue
                    err = True
                if not err:
                    return case
                """
        return None

    def list_resolve(self, data):
        if type(data) != list and type(data) != tuple:
            return data

        print("ENT ", data)
        item = data
        litem = len(item)

        for case, rules in self.language.items():
            for rule in rules:
                if len(rule) > litem:
                    continue

                lr = len(rule)
                df = litem - lr
                for pos in range(0, df + 1):
                    err = False
                    print("MM", pos, rule, item[pos:pos+lr])
                    for a,b in zip(rule, item[pos:pos+lr]):
                        if a == b:
                            continue
                        if type(b) == ParserItem and b.matches(a):
                            continue
                        err = True
                    if not err:
                        ntmp = None
                        if lr == 1:
                            if type(item[pos]) == ParserItem:
                                ntmp = item[pos]
                        if ntmp is None:
                            ntmp = ParserItem(item[pos:pos+lr])
                            ntmp.reduce(case)
                        nl = item[:pos] + [ntmp] + item[pos+lr:]
                        print("MATCH", case, pos, rule, item, "-> ", nl)
                        print("MP1", item[:pos])
                        print("MP2", case, ntmp)
                        print("MP3", item[pos+lr:])
                        print(" NL", nl)
                        if nl == item:
                            return nl
                        return self.list_resolve(nl)
        return data

    def reduce(self, item, tgt=None):
        if item is None:
            return None
        #if type(item) == ParserItem and item.matches(tgt):
        #    return item

        if type(item) == ParserItem:
            mapped = item.get()
            print ("MP", mapped)
            while True:
                mapped = self.map_one_item(mapped)
                if mapped is None:
                    break
                item.reduce(mapped)
            return item
        elif type(item) == list or type(item) == tuple:
            mapped = [self.reduce(i) for i in item]
            print("MPL", mapped)
            res = ParserItem(item)
            nitem = self.list_resolve(mapped)
            print("NITEM", nitem)
            """
            nitem = mapped
            while nitem is not None:
                nitem = self.map_list_item(nitem)
                if nitem is not None:
                    res.reduce(nitem)
            """
            print("ITM", item)
            #item = mapped
            #mapped = self.map_list_item(item)
        else:
            raise ValueError("Invalid type in reduction: {}, item: {}".format(type(item), item))
        if mapped is None or not mapped:
            return item

        return item

        """
        if type(item) == Token:
            mapped = self.map_one_item(item.tokentype)
        elif type(item) == TokenType:
            mapped = self.map_one_item(item)
        elif type(item) == str:
            mapped = self.map_one_item(item)
        elif type(item) == list or type(item) == tuple:
            mapped = self.map_list_item(item)
        else:
            raise ValueError("Invalid type in reduction: {}, item: {}".format(type(item), item))
        if mapped is None or not mapped:
            return item
        if mapped == tgt:
            return mapped

        # Reduce as much as possible
        re = self.can_reduce(mapped, tgt)
        if re is not None:
            return re

        return mapped
        """

        """
        if item is None:
            return None
        if item == tgt:
            return item

        if type(item) == Token:
            mapped = self.map_one_item(item.tokentype)
        elif type(item) == TokenType:
            mapped = self.map_one_item(item)
        elif type(item) == str:
            mapped = self.map_one_item(item)
        elif type(item) == list or type(item) == tuple:
            mapped = self.map_list_item(item)
        else:
            raise ValueError("Invalid type in reduction: {}, item: {}".format(type(item), item))
        if mapped is None or not mapped:
            return item
        if mapped == tgt:
            return mapped

        # Reduce as much as possible
        re = self.can_reduce(mapped, tgt)
        if re is not None:
            return re

        return mapped
        """

    def parse(self):
        stack = []
        while True:
            item = self.scan.scan()
            if item is None:
                break
            stack.append(ParserItem(item))
            print(">INPUT", stack)
            nstack = self.reduce(stack)
            if nstack is None:
                print("Nomatch!", stack)
                continue
            if type(nstack) == tuple:
                stack = list(nstack)
            elif type(nstack) != list:
                stack = [nstack]
            print("= RES ", stack)
        """
        return self.translation_unit()

    def translation_unit(self):
        extdec = self.external_declaration()
        if extdec is None:
            return None
        return None

    def external_declaration(self):
        return None
        """
