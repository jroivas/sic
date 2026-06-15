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
import llvmlite.ir as ll
from llvmlite import binding

#class SignedIntType(object):
#class SignedIntType(ll.Type):
class SignedIntType(ll.IntType):
    """
    The type for signed integers.
    """
    _instance_cache = {}
    width: int

    def __new__(cls, bits):
        # Cache all common integer types
        if 0 <= bits <= 128:
            try:
                return cls._instance_cache[bits]
            except KeyError:
                inst = cls._instance_cache[bits] = cls.__new(bits)
                return inst
        return cls.__new(bits)

    @classmethod
    def __new(cls, bits):
        assert isinstance(bits, int) and bits >= 0
        self = super(SignedIntType, cls).__new__(cls, bits)
        self.width = bits
        return self

    def _to_string(self):
        return 'i%u' % (self.width,)


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
        self.globals = {}
        self.current_decl_type = None
        self.current_func_ret_type = SignedIntType(32)

        # TODO Configurable target
        #binding.initialize_all_targets()
        binding.initialize_native_target()
        binding.initialize_native_asmprinter()

        self.target = binding.Target.from_default_triple()
        self.target_machine = self.target.create_target_machine()
        self.module.triple = self.target_machine.triple

        self.typemap = {}

    def gen_name(self):
        self.gen_idx += 1
        return "__{}".format(self.gen_idx)

    def convert(self, target, val):
        if target == val.type:
            return val

        if target == ll.DoubleType():
            if isinstance(val.type, SignedIntType):
                return self.builder.sitofp(val, target)
            elif isinstance(val.type, ll.IntType):
                return self.builder.uitofp(val, target)
        elif isinstance(target, SignedIntType):
            if isinstance(val.type, ll.DoubleType):
                return self.builder.fptosi(val, target)
            elif isinstance(val.type, ll.IntType):
                if val.type.width < target.width:
                    if isinstance(val.type, SignedIntType):
                        return self.builder.sext(val, target)
                    else:
                        return self.builder.zext(val, target)
                elif val.type.width > target.width:
                    return self.builder.trunc(val, target)
                else:
                    val.type = target
                    return val
        elif isinstance(target, ll.IntType):
            if isinstance(val.type, ll.DoubleType):
                return self.builder.fptoui(val, target)
            elif isinstance(val.type, SignedIntType):
                if val.type.width < target.width:
                    return self.builder.zext(val, target)
                elif val.type.width > target.width:
                    return self.builder.trunc(val, target)
                else:
                    val.type = target
                    return val

        print(isinstance(target, ll.IntType))
        print(isinstance(val.type, ll.DoubleType))
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
        if isinstance(ta, SignedIntType) and isinstance(tb, ll.IntType):
            if ta.width >= tb.width:
                return ta
            return SignedIntType(tb.width)
        elif isinstance(ta, ll.IntType) and isinstance(tb, SignedIntType):
            if tb.width >= ta.width:
                return tb
            return SignedIntType(ta.width)
        elif isinstance(ta, ll.IntType) and isinstance(tb, ll.IntType):
            if ta.width >= tb.width:
                return ta
            return tb
        elif isinstance(ta, ll.DoubleType) and isinstance(tb, ll.IntType):
            return ta
        elif isinstance(tb, ll.DoubleType) and isinstance(ta, ll.IntType):
            return tb

        raise ValueError("Invalid type determination {} and {}".format(ta, tb))

    def to_int(self, val):
        return sic.tools.to_int(val)

    def _is_type_spec(self, val):
        if isinstance(val, AstNode) and val.nodetype == AstType.TYPE:
            return True
        if type(val) == AstPair:
            return self._is_type_spec(val.l) and self._is_type_spec(val.r)
        if type(val) == list:
            return bool(val) and all(self._is_type_spec(i) for i in val)
        return False

    def _collect_type_keywords(self, val):
        if isinstance(val, AstNode) and val.nodetype == AstType.TYPE:
            inner = val.value
            if isinstance(inner, AstNode) and inner.nodetype == AstType.TYPE:
                return [inner.value]
            elif isinstance(inner, str):
                return [inner]
            return []
        if type(val) == AstPair:
            return self._collect_type_keywords(val.l) + self._collect_type_keywords(val.r)
        if type(val) == list:
            result = []
            for item in val:
                result.extend(self._collect_type_keywords(item))
            return result
        return []

    def _llvm_type_from_keywords(self, keywords):
        unsigned = 'unsigned' in keywords
        if 'char' in keywords:
            return ll.IntType(8) if unsigned else SignedIntType(8)
        elif 'short' in keywords:
            return ll.IntType(16) if unsigned else SignedIntType(16)
        elif 'long' in keywords:
            return ll.IntType(64) if unsigned else SignedIntType(64)
        elif 'double' in keywords:
            return ll.DoubleType()
        elif 'float' in keywords:
            return ll.FloatType()
        else:  # int, unsigned, or unsigned int
            return ll.IntType(32) if unsigned else SignedIntType(32)

    def _resolve_type_spec(self, spec):
        return self._llvm_type_from_keywords(self._collect_type_keywords(spec))

    def _get_initializer_const(self, val, target_type):
        """Return an ll.Constant for use as a global initializer, without side effects."""
        if type(val) == AstLiteral and val.nodetype == AstType.INT_LIT:
            return ll.Constant(target_type, self.to_int(val.value))
        elif type(val) == AstLiteral and val.nodetype == AstType.FRAC_LIT:
            return ll.Constant(target_type, float(val.value))
        return None

    def _extract_func_name(self, declarator):
        if type(declarator) == AstPair:
            return self._extract_func_name(declarator.l)
        if isinstance(declarator, AstNode) and declarator.nodetype == AstType.IDENTIFIER:
            return declarator.value
        return None

    def _generate(self, val):
        if val is None:
            return None

        if type(val) == AstPair:
            if self._is_type_spec(val.l):
                self.current_decl_type = self._resolve_type_spec(val.l)
                return self._generate(val.r)
            a = self._generate(val.l)
            b = self._generate(val.r)
            return [a, b]
        elif type(val) == AstNode and val.nodetype in (AstType.OP, AstType.ASSIGNMENT):
            return val.value
        elif type(val) == AstOpNode:
            op = self._generate(val.op)

            if op == "=":
                if isinstance(val.left, AstNode) and val.left.nodetype == AstType.IDENTIFIER:
                    name = val.left.value
                    if name not in self.globals:
                        decl_type = self.current_decl_type or ll.IntType(32)
                        gv = ll.GlobalVariable(self.module, decl_type, name)
                        init = self._get_initializer_const(val.right, decl_type)
                        if init is None:
                            rhs = self._generate(val.right)
                            rhs_val = self.load(rhs)
                            gv.initializer = ll.Constant(decl_type, 0)
                            self.builder.store(rhs_val, gv)
                        else:
                            gv.initializer = init
                        self.globals[name] = gv
                        self.last_initializer = gv
                        return gv
                    else:
                        gv = self.globals[name]
                        rhs = self._generate(val.right)
                        self.builder.store(self.load(rhs), gv)
                        return gv
                else:
                    raise ValueError("Unsupported = target: {}".format(val.left))

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
            elif op == "*":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.fmul(a, b)
                else:
                    sv = self.builder.mul(a, b)
                self.last_initializer = sv
                return sv
            elif op == "/":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.fdiv(a, b)
                elif isinstance(ttype, SignedIntType):
                    # FIXME
                    sv = self.builder.sdiv(a, b)
                else:
                    sv = self.builder.udiv(a, b)
                self.last_initializer = sv
                return sv
            elif op == "%":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.frem(a, b)
                else:
                    sv = self.builder.urem(a, b)
                self.last_initializer = sv
                return sv
            else:
                raise ValueError("Unsupported op: {} (orig {})".format(op, val.op))
        elif type(val) == AstLiteral:
            if val.nodetype == AstType.INT_LIT or val.nodetype == AstType.FRAC_LIT:
                # TODO Different sizes
                if val.nodetype == AstType.INT_LIT:
                    ival = self.to_int(val.value)
                    bl = ival.bit_length()
                    if bl <= 32:
                        if ival < 0:
                            thetype = SignedIntType(32)
                            #print("TT2", thetype)
                        else:
                            thetype = ll.IntType(32)
                    elif bl <= 64:
                        if ival < 0:
                            thetype = SignedIntType(64)
                        else:
                            thetype = ll.IntType(64)
                    else:
                        raise ValueError("Integer overflow bits: {}".format(bl))
                    #print("TYPE", thetype, str(thetype), repr(thetype))
                    #print(" DD", dir(thetype))
                    if ival < 0:
                        neg = True
                    cv = ll.Constant(thetype, ival)
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
        elif type(val) == AstUnary:
            a_val = self._generate(val.value)
            a = self.load(a_val)
            ttype = a.type

            if val.op.value == "-":
                if isinstance(ttype, ll.DoubleType):
                    sv = self.builder.fneg(a)
                else:
                    # Force type to signed if not
                    if not isinstance(ttype, SignedIntType):
                        a.type = SignedIntType(a.type.width)
                    sv = self.builder.neg(a)
                    #print("sv" ,sv.type, sv)
                self.last_initializer = sv
                return sv
        elif type(val) == AstNode and val.nodetype == AstType.IDENTIFIER:
            name = val.value
            if name in self.globals:
                return self.globals[name]
            # Bare declarator (no initializer) in a declaration context
            if self.current_decl_type is not None:
                decl_type = self.current_decl_type
                gv = ll.GlobalVariable(self.module, decl_type, name)
                gv.initializer = ll.Constant(decl_type, 0)
                self.globals[name] = gv
                self.last_initializer = gv
                return gv
            raise ValueError("Undefined identifier: {}".format(name))
        elif type(val) == AstNode and val.nodetype == AstType.FUNCDEF:
            parts = val.value
            body = parts[-1]
            if len(parts) >= 3:
                decl_spec = parts[0]
                declarator = parts[1]
            else:
                decl_spec = None
                declarator = parts[0]

            if decl_spec is not None and self._is_type_spec(decl_spec):
                ret_type = self._resolve_type_spec(decl_spec)
            else:
                ret_type = SignedIntType(32)

            name = self._extract_func_name(declarator)
            if name is None:
                return None

            if name == 'main':
                self.got_main = True

            saved_last = self.last_initializer
            saved_is_global = self.is_global
            saved_decl_type = self.current_decl_type
            saved_ret_type = self.current_func_ret_type

            fntype = ll.FunctionType(ret_type, [])
            func = ll.Function(self.module, fntype, name=name)
            entry = func.append_basic_block()
            self.builder.position_at_end(entry)
            self.is_global = False
            self.current_func_ret_type = ret_type
            self._generate(body)

            self.last_initializer = saved_last
            self.is_global = saved_is_global
            self.current_decl_type = saved_decl_type
            self.current_func_ret_type = saved_ret_type
            return func

        elif type(val) == AstNode and val.nodetype == AstType.BLOCK:
            return self._generate(val.value)

        elif type(val) == AstNode and val.nodetype == AstType.KEYWORD:
            if isinstance(val.value, list) and len(val.value) >= 2 and val.value[0] == 'return':
                expr = self._generate(val.value[1])
                ret_val = self.load(expr)
                ret_val = self.convert(self.current_func_ret_type, ret_val)
                self.builder.ret(ret_val)
                return ret_val
            elif val.value == 'return':
                self.builder.ret(ll.Constant(self.current_func_ret_type, 0))
                return None

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
        res = self.convert(SignedIntType(32), res)
        self.builder.ret(res)

    def generate(self):
        genres = self._generate(self.ast)

        if self.last_initializer:
            self.builder.position_at_end(self.init_entry)
            last = self.load(self.last_initializer)
            lastval = self.convert(SignedIntType(32), last)
            self.builder.ret(lastval)

        if not self.got_main:
            self.fake_main()

        if genres:
            res = "{}".format(self.module)
            return res


def Codegen(ast, name):
    return LLVMLiteCodegen(ast, name)
