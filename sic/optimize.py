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
    AstTypedef,
    AstPair,
    AstLiteral,
    AstUnary,
)
import sic.tools

class Optimize(object):
    def __init__(self, ast, lvl):
        self.ast = ast
        self.lvl = lvl

    def handle_simple_unary(self, val):
        if type(val.op) == AstNode and val.op.nodetype == AstType.UNARY:
            op = val.op.value
        else:
            return val

        vv = val.value
        if isinstance(vv, AstNode):
            if vv.nodetype == AstType.INT_LIT:
                if op == "-" and vv.value:
                    if vv.value[0] != '-':
                        vv.value = "-" + vv.value
                    else:
                        vv.value = vv.value[1:]
                return vv
            elif vv.nodetype == AstType.FRAC_LIT:
                if op == "-" and vv.value:
                    if vv.value[0] != '-':
                        vv.value = "-" + vv.value
                    else:
                        vv.value = vv.value[1:]
                return vv

        return val

    def handle_simple_op(self, v):
        if type(v.op) == AstNode and v.op.nodetype == AstType.OP:
            op = v.op.value
        else:
            return v

        v.left = self.walk(v.left)
        v.right = self.walk(v.right)

        if type(v.left) == AstLiteral and type(v.right) == AstLiteral:
            rt = v.left
            if v.left.nodetype == AstType.INT_LIT:
                v1 = sic.tools.to_int(v.left.value)
            elif v.left.nodetype == AstType.FRAC_LIT:
                v1 = float(v.left.value)

            if v.right.nodetype == AstType.INT_LIT:
                v2 = sic.tools.to_int(v.right.value)
            elif v.right.nodetype == AstType.FRAC_LIT:
                v2 = float(v.right.value)
                rt = v.right

            if op == "+":
                rt.value = v1 + v2
                return rt
            elif op == "-":
                rt.value = v1 - v2
                return rt
            elif op == "*":
                rt.value = v1 * v2
                return rt
            elif op == "/" and v2 != 0:
                rt.value = v1 / v2
                return rt
            elif op == "%" and v2 != 0:
                rt.value = v1 % v2
                return rt

        return v

    def walk(self, v):
        #print("WLK", v)
        if v is None:
            return None

        if type(v) == AstUnary:
            return self.handle_simple_unary(v)
        elif type(v) == AstNode and v.nodetype == AstType.OP:
            return v
        elif type(v) == AstPair:
            v.l = self.walk(v.l)
            v.r = self.walk(v.r)
            return v
        elif type(v) == AstOpNode:
            return self.handle_simple_op(v)
            #v.left = self.walk(v.left)
            #v.right = self.walk(v.right)
            #return v
        elif type(v) == AstLiteral:
            return v
        elif isinstance(v, AstNode):
            v.value = self.walk(v.value)
            return v
        elif type(v) == list:
            tmp = []
            for i in v:
                tmp.append(self.walk(i))
            return tmp
        else:
            raise ValueError("Unknown node: {}".format(v))

    def run(self):
        return self.walk(self.ast)
