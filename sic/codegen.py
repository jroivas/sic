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

            if isinstance(a_val.type, ll.PointerType):
                a = self.builder.load(a_val)
            else:
                a = a_val

            if isinstance(b_val.type, ll.PointerType):
                b = self.builder.load(b_val)
            else:
                b = b_val

            if op == "+":
                sv = self.builder.add(a, b)
                self.last_initializer = sv
                return sv
            elif op == "-":
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
            if val.nodetype == AstType.INT_LIT:
                # TODO Different sizes
                cv = ll.Constant(ll.IntType(32), int(val.value))

                if self.is_global:
                    iv = ll.GlobalVariable(self.module, ll.IntType(32), self.gen_name())
                    iv.global_constant = True
                    iv.initializer = cv
                    self.last_initializer = iv
                    return iv
                else:
                    iv = self.builder.alloca(ll.IntType(32))
                    self.builder.store(cv, iv)
                    return builder.load(iv)
                """
                if self.is_global:
                    iv = ll.()
                else:
                    iv = self.builder.alloca(ll.IntType(32))
                    self.builder.store(ll.Constant(iv.type.pointee, int(val.value)), iv)
                    return builder.load(iv)
                """
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
            self.builder.ret(self.last_initializer)

        if not self.got_main:
            self.fake_main()

        if genres:
            res = "{}".format(self.module)
            return res


def Codegen(ast, name):
    return LLVMLiteCodegen(ast, name)
