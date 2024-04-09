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
