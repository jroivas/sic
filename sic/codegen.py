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
)
import llvmlite.ir as ll
from llvmlite import binding

class BaseCodegen(object):
    def __init__(self, ast, name):
        self.ast = ast
        self.name = name

    def generate(self):
        pass

class LLVMLiteCodegen(BaseCodegen):
    def __init__(self, ast, name):
        super().__init__(ast, name)
        self.module = ll.Module(name)
        #self.ctx = ll.Context()
        self.builder = ll.IRBuilder()
        self.is_global = True
        self.gen_idx = 0

        self.init_fntype = ll.FunctionType(ll.IntType(32), [])
        self.init_func = ll.Function(self.module, self.init_fntype, name='__sic_init_func')
        self.init_entry = self.init_func.append_basic_block()
        self.builder.position_at_end(self.init_entry)

        self.last_initializer = None

        self.got_main = False

        # TODO Configurable target
        binding.initialize()
        #binding.initialize_all_targets()
        binding.initialize_native_target()

        self.target = binding.Target.from_default_triple()
        self.target_machine = self.target.create_target_machine()
        self.module.triple = self.target_machine.triple

    def gen_name(self):
        self.gen_idx += 1
        return "__{}".format(self.gen_idx)

    def convert(self, target, val):
        if target == val.type:
            return val

        if target == ll.DoubleType():
            if isinstance(val.type, ll.IntType):
                # FIXME Signed
                return self.builder.uitofp(val, target)
        elif isinstance(target, ll.IntType):
            if isinstance(val.type, ll.DoubleType):
                return self.builder.fptoui(val, target)

        raise ValueError("Unknown convert to {} from {}".format(target, val))

    def load(self, val):
        if isinstance(val.type, ll.PointerType):
            return self.builder.load(val)

        return val

    def ttype(self, a, b):
        ta = a.type
        tb = b.type
        if ta == tb:
            return ta
        if isinstance(ta, ll.IntType) and isinstance(tb, ll.IntType):
            if ta.width >= tb.width:
                return ta
            return tb
        if isinstance(ta, ll.DoubleType) and isinstance(tb, ll.IntType):
            return ta
        if isinstance(tb, ll.DoubleType) and isinstance(ta, ll.IntType):
            return tb

        raise ValueError("Invalid type determination {} and {}".format(ta, tb))

    def _generate(self, val):
        if val is None:
            return None

        if type(val) == AstPair:
            a = self._generate(val.l)
            b = self._generate(val.r)
            return [a, b]
        elif type(val) == AstNode and val.nodetype == AstType.OP:
            return val.value
        elif type(val) == AstOpNode:
            op = self._generate(val.op)
            a_val = self._generate(val.left)
            b_val = self._generate(val.right)
            #print(dir(a_val))
            #print(a_val.type)
            #print(a_val)
            #print(b_val)

            a = self.load(a_val)
            b = self.load(b_val)
            ttype = self.ttype(a, b)
            a = self.convert(ttype, a)
            b = self.convert(ttype, b)

            if op == "+":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.fadd(a, b)
                else:
                    sv = self.builder.add(a, b)
                self.last_initializer = sv
                return sv
            elif op == "-":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.fsub(a, b)
                else:
                    sv = self.builder.sub(a, b)
                self.last_initializer = sv
                return sv
            else:
                raise ValueError("Unsupported op: {} (orig {])".format(op, val.op))
                """
                a = self._generate(val.left)
                b = self._generate(val.right)
                return [val.op, a, b]
                """
        elif type(val) == AstLiteral:
            if val.nodetype == AstType.INT_LIT or val.nodetype == AstType.FRAC_LIT:
                # TODO Different sizes
                if val.nodetype == AstType.INT_LIT:
                    thetype = ll.IntType(32)
                    cv = ll.Constant(thetype, int(val.value))
                elif val.nodetype == AstType.FRAC_LIT:
                    # FIXME Float
                    thetype = ll.DoubleType()
                    cv = ll.Constant(thetype, float(val.value))

                if self.is_global:
                    iv = ll.GlobalVariable(self.module, thetype, self.gen_name())
                    iv.global_constant = True
                    iv.initializer = cv
                    self.last_initializer = iv
                    return iv
                else:
                    iv = self.builder.alloca(thetype)
                    self.builder.store(cv, iv)
                    return builder.load(iv)
            else:
                raise ValueError("Unsupported literal: {}".format(val))
            #return val.value
        elif isinstance(val, AstNode):
            if val.value:
                return self._generate(val.value)
            return None
        elif type(val) == list:
            res = []
            for i in val:
                v = self._generate(i)
                if v is not None:
                    res.append(v)
            return res
        else:
            raise ValueError("Unknown value: {}".format(val))

    def fake_main(self):
        # Can't have void ptr, so using ptr to i8
        self.main_fntype = ll.FunctionType(ll.IntType(32), [ll.IntType(32), ll.PointerType(ll.PointerType(ll.IntType(8)))])
        self.main_func = ll.Function(self.module, self.main_fntype, name='main')
        self.main_entry = self.main_func.append_basic_block()
        self.builder.position_at_end(self.main_entry)

        res = self.builder.call(self.init_func, [])
        self.builder.ret(res)

    def generate(self):
        genres = self._generate(self.ast)

        if self.last_initializer:
            self.builder.position_at_end(self.init_entry)
            lastval = self.convert(ll.IntType(32), self.last_initializer)
            self.builder.ret(lastval)

        if not self.got_main:
            self.fake_main()

        if genres:
            res = "{}".format(self.module)
            return res


def Codegen(ast, name):
    return LLVMLiteCodegen(ast, name)
