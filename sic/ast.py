from enum import Enum

class AstType(Enum):
    ROOT = 0
    INT_LIT = 1
    FRAC_LIT = 2
    STR_LIT = 3
    IDENTIFIER = 4
    NODE = 5
    OP = 6
    POINTER = 7
    BLOCK = 8
    TYPE = 9

class AstNode(object):
    def __init__(self, nodetype, value):
        self.nodetype = nodetype
        self.value = value

    def __repr__(self):
        return "AstNode({},{})".format(self.nodetype, self.value)

    def list_to_json(self, data):
        res = []
        for i in data:
            if isinstance(i, AstNode):
                res.append(i.to_json())
            elif type(i) == list or type(i) == list:
                res.append(self.list_to_json(i))
            elif type(i) == str:
                res.append(i)
            else:
                raise ValueError("unk", type(i))
        return res

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "value": []
        }
        if type(self.value) == list or type(self.value) == tuple:
            res["value"] = self.list_to_json(self.value)
        elif isinstance(self.value, AstNode):
            res["value"] = self.value.to_json()
        elif type(self.value) == str:
            res["value"] = self.value
        else:
            raise ValueError("Daa", self.value)
        return res

class AstOpNode(AstNode):
    def __init__(self, optype, a, b):
        self.op = optype
        self.left = a
        self.right = b
        super().__init__(AstType.OP, [optype, a, b])

    def __repr__(self):
        return "AstOpNode({} {} {})".format(self.left, self.op, self.right)

    def to_json(self):
        ljs = self.left
        rjs = self.right
        if isinstance(ljs, AstNode):
            ljs = ljs.to_json()
        if isinstance(rjs, AstNode):
            rjs = rjs.to_json()

        res = {
            "type": "{}".format(self.nodetype),
            "value": self.op,
            self.op:
            {
                "left": ljs,
                "right": rjs,
            }
        }
        return res
