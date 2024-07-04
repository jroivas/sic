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
    FUNCDEF = 10
    SQUARE = 11
    KEYWORD = 12
    TYPE_QUAL = 13
    UNARY = 14
    IF = 16
    CMP = 17
    TYPE_LIST = 18
    TERNARY = 19
    WHILE = 20
    DO = 21
    FOR = 22
    SIZEOF = 23
    TYPE_STORAGE = 24
    STRUCT = 25
    UNION = 26
    ENUM = 27
    GOTO = 28
    BREAK = 29
    CONTINUE = 30
    LABEL = 31
    CASE = 32
    OP_PRE = 33
    OP_POST = 34
    CAST = 35
    INITIALIZER = 36
    ATOMIC = 37
    ALIGN_AS = 38
    VA_ARG = 39
    PARENTHESIS = 40


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
        res = {"type": "{}".format(self.nodetype), "value": []}
        if type(self.value) == list or type(self.value) == tuple:
            res["value"] = self.list_to_json(self.value)
        elif isinstance(self.value, AstNode):
            res["value"] = self.value.to_json()
        elif type(self.value) == str:
            res["value"] = self.value
        else:
            raise ValueError("Daa", self.value)
        return res

    def obj_to_json(self, val):
        # if val is None:
        #    return None
        if isinstance(val, AstNode):
            val = val.to_json()
        elif type(val) == list or type(val) == tuple:
            val = self.list_to_json(val)
        return val


class AstOpNode(AstNode):
    def __init__(self, optype, a, b):
        self.op = optype
        self.left = a
        self.right = b
        super().__init__(AstType.OP, [optype, a, b])

    def __repr__(self):
        return "AstOpNode({} {} {})".format(self.left, self.op, self.right)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "value": self.op,
            self.op: {
                "left": self.obj_to_json(self.left),
                "right": self.obj_to_json(self.right),
            },
        }
        return res


class AstPrePostOp(AstNode):
    def __init__(self, optype, val, pre=False):
        self.op = optype
        self.val = val
        self.pre = pre
        super().__init__(AstType.OP_PRE if pre else AstType.OP_POST, [optype, val])

    def __repr__(self):
        if self.pre:
            return "AstPreOp({} {}) ".format(self.op, self.val)
        else:
            return "AstPostOp({} {})".format(self.val, self.op)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "op": self.op,
            "value": self.obj_to_json(self.val),
            "pre": self.pre,
        }
        return res


class AstPointer(AstNode):
    def __init__(self, value, lvl=1):
        super().__init__(AstType.POINTER, value)
        self.lvl = lvl

    def __repr__(self):
        return "AstPointer({} {})".format(self.lvl, self.value)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "level": self.lvl,
            "value": self.obj_to_json(self.value),
        }
        return res


class AstIf(AstNode):
    def __init__(self, cond, true, false=None, ternary=False):
        op = AstType.IF
        if ternary:
            op = AstType.TERNARY
        super().__init__(op, [cond, true, false])
        self.cond = cond
        self.true = true
        self.false = false

    def __repr__(self):
        return "AstIf({} {})".format(self.cond, self.true, self.false)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "cond": self.obj_to_json(self.cond),
            "true": self.obj_to_json(self.true),
            "false": self.obj_to_json(self.false),
        }
        return res


class AstLoop(AstNode):
    def __init__(self, looptype, cond, loop, init=None, post=None):
        op = looptype
        super().__init__(op, [cond, loop])
        self.cond = cond
        self.loop = loop
        self.init = init
        self.post = post
        # self.elseblock = elseblock

    def __repr__(self):
        return "AstLoop({} {})".format(
            self.nodetype, self.cond, self.cond, self.loop, self.post
        )

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "cond": self.obj_to_json(self.cond),
            "loop": self.obj_to_json(self.loop),
            "init": self.obj_to_json(self.init),
            "post": self.obj_to_json(self.post),
            # "else": self.obj_to_json(self.elseblock)
        }
        return res


class AstStruct(AstNode):
    def __init__(self, union_struct, name, data):
        tpe = AstType.STRUCT
        super().__init__(tpe, [union_struct, name, data])
        self.union_struct = union_struct
        self.name = name
        self.data = data

    def __repr__(self):
        return "AstStruct({} {})".format(self.union_struct, self.name)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "union_struct": self.obj_to_json(self.union_struct),
            "name": self.name if self.name else "",
            "data": self.obj_to_json(self.data),
        }
        return res


class AstEnum(AstNode):
    def __init__(self, name, data):
        super().__init__(AstType.ENUM, [name, data])
        self.name = name
        self.data = data

    def __repr__(self):
        return "AstEnum({} {})".format(self.name, self.data)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "name": self.name if self.name else "",
            "data": self.obj_to_json(self.data),
        }
        return res


class AstGoto(AstNode):
    def __init__(self, gtype, target=None):
        self.target = target
        super().__init__(gtype, target)

    def __repr__(self):
        return "AstGoto({} {})".format(self.nodetype, self.target)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "target": self.obj_to_json(self.target),
        }
        return res


class AstLabel(AstNode):
    def __init__(self, name, value=None, case=False):
        self.name = name
        self.value = value
        tt = AstType.LABEL
        if case:
            tt = AstType.CASE
        if value:
            super().__init__(tt, name)
        else:
            super().__init__(tt, [name, value])

    def __repr__(self):
        if self.nodetype == AstType.CASE:
            return "AstCase({} {})".format(self.name, self.value)
        else:
            return "AstLabel({} {})".format(self.name, self.value)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "name": "{}".format(self.name),
            "value": self.obj_to_json(self.value),
        }
        return res

class AstCast(AstNode):
    def __init__(self, target, src):
        self.target = target
        self.src = src

        super().__init__(AstType.CAST, [target, src])

    def __repr__(self):
        return "AstCast({} {})".format(self.target, self.src)

    def to_json(self):
        res = {
            "type": "{}".format(self.nodetype),
            "to": "{}".format(self.target),
            "src": self.obj_to_json(self.src),
        }
        return res
