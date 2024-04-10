from enum import Enum

class AstType(Enum):
    INT_LIT = 1
    FRAC_LIT = 2
    STR_LIT = 3
    IDENTIFIER = 4
    NODE = 5
    OP = 6

class AstNode(object):
    def __init__(self, nodetype, value):
        self.nodetype = nodetype
        self.value = value

    def __repr__(self):
        return "AstNode({},{})".format(self.nodetype, self.value)

class AstOpNode(AstNode):
    def __init__(self, optype, a, b):
        self.op = optype
        self.left = a
        self.right = b
        super().__init__(AstType.OP, [optype, a, b])

    def __repr__(self):
        return "AstOpNode({} {} {})".format(self.left, self.op, self.right)
