from sic.token import TokenType, Token
from sic.scan import Scan


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


class Parser:
    def __init__(self, scan, lang):
        self.scan = scan
        self.ast = {}
        self.language = lang

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
        litem = len(item)
        if type(item) != tuple:
            item = tuple(item)

        for case, rules in self.language.items():
            for rule in rules:
                if len(rule) != litem:
                    continue

                err = False
                for a,b in zip(rule, item):
                    if a == b:
                        continue
                    if self.can_reduce(b, a):
                        continue
                    err = True
                if not err:
                    return case
        return None

    def can_reduce(self, item, tgt):
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

    def reduce(self, item):
        return self.can_reduce(item, None)

    def parse(self):
        stack = []
        while True:
            item = self.scan.scan()
            if item is None:
                break
            stack.append(item)
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
