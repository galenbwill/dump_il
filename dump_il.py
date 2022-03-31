import functools

from binaryninja import *

from .binja_tqdm import tqdm

from .metrics import metrics

# Note that this is a sample plugin and you may need to manually edit it with
# additional functionality. In particular, this example only passes in the
# binary view. If you would like to act on an addres or function you should
# consider using other register_for* functions.

# Add documentation about UI plugin alternatives and potentially getting
# current_* functions


log = binaryninja.log_info

# @functools.cache

_interesting_type_cache = dict()


def _interesting_type(t, in_array=False):
    tc = t.type_class
    if tc == TypeClass.FloatTypeClass:
        return True
    elif in_array and tc == TypeClass.IntegerTypeClass:
        return True
    elif tc == TypeClass.ArrayTypeClass:
        return interesting_type(t.element_type, in_array=True)
    elif tc == TypeClass.PointerTypeClass:
        return interesting_type(t.target, in_array)
    return False


def interesting_type(t, in_array=False):
    key = f'{t!r}#{in_array}'
    if key in _interesting_type_cache:
        return _interesting_type_cache[key]
    interesting = _interesting_type(t, in_array)
    _interesting_type_cache[key] = interesting
    return interesting


def _interesting(o):
    return 'LIL_F' in o and 'LLIL_FLAG' not in o and 'LIL_FOR' not in o and 'MLIL_FREE_VAR_SLOT' not in o


intrinsic_operations = {
    'hlil': HighLevelILOperation.HLIL_INTRINSIC,
    'mlil': MediumLevelILOperation.MLIL_INTRINSIC,
    'llil': LowLevelILOperation.LLIL_INTRINSIC,
    'hlil_ssa': HighLevelILOperation.HLIL_INTRINSIC,
    'mlil_ssa': MediumLevelILOperation.MLIL_INTRINSIC,
    'llil_ssa': LowLevelILOperation.LLIL_INTRINSIC,
    'lifted_il': LowLevelILOperation.LLIL_INTRINSIC,
}

interesting_operations = defaultdict(set)
for il, enum in {
    'llil': LowLevelILOperation,
    'lifted_il': LowLevelILOperation,
    'mlil': MediumLevelILOperation,
    'hlil': HighLevelILOperation,
}.items():
    for m in enum:
        if _interesting(m.name):
            interesting_operations[il].add(m)
            interesting_operations[il + '_ssa'].add(m)


@functools.cache
def interesting_intrinsic(index, a, filter=True):
    name, info = a._intrinsics_by_index[index]
    for input in info.inputs:
        if not filter or interesting_type(input.type):
            return info


def interesting(i, il, filter=True):
    if not hasattr(i, 'operation'):
        return False
    if i.operation == intrinsic_operations[il]:
        a = i.function.arch
        return interesting_intrinsic(i.intrinsic.index, a, filter)
    else:
        try:
            return not filter or i.operation in interesting_operations[il]
        except Exception as e:
            log_warn(f'{i} operation {i.operation!r} {type(i.operation)!r}: {e}')
    return False


def dump_il_instr(i, il, lines, indent=0, filter=True):
    # log_debug(f'i: {type(i)} {i!r}')
    if hasattr(i, 'operation'):
        # if 'HLIL_F' in repr(i.operation) and not 'FLOAT_CONV' in repr(i.operation):
        is_interesting = interesting(i, il, filter)
        if is_interesting:
            lines.append('  ' * indent + f'{i.address:#x} {i.operation.name}')
            if hasattr(i, 'intrinsic'):
                lines[-1] += f' [{i.intrinsic} {is_interesting}]'
            if i.size:
                dsm = i.function.view.get_disassembly(i.address)
                if dsm:
                    lines[-1] += ' => ' + dsm
        if hasattr(i, 'operands'):
            for ii in i.operands:
                if isinstance(ii, BaseILInstruction):
                    dump_il_instr(ii, il, lines, indent + 1)

def get_il(func, il):
    if il.endswith('_ssa'):
        il_il = getattr(func, il[:-4])
        il_il = il_il.ssa_form
    else:
        il_il = getattr(func, il)
    return il_il


def dump_il(h, il='hlil', filter=True):
    lines = []
    if type(h) is Function:
        lines = dump_il(get_il(h, il), il, filter)
    elif isinstance(h, BasicBlock) and h.is_il:
        # print('block', b)
        for i in h:
            dump_il_instr(i, il, lines, 1, filter)
    elif hasattr(h, 'source_function'):
        i = get_il(h.source_function, il)
        # log_debug(f'h: {h!r}\nf: {f!r}')
        # i = getattr(f, il)
        if h != i:
            lines = dump_il(i, il, filter)
        else:
            for b in h.basic_blocks:
                lines += dump_il(b, il, filter)
            if lines:
                lines = [f'{h.source_function.name}, {h.source_function.start:#x}, {h.source_function}'] + lines + ['\n']
    else:
        # log_debug(f'not a thing: {type(h)}: {h!r}')
        dump_il_instr(h, il, lines, 1, filter)
    return lines

def dump_il_func(f, il='hlil', alert=True, timeit=True, filter=True):
    @metrics(hms=True, alert=alert, timeit=timeit)
    def _dump_il_func(f, il='hlil', alert=True, filter=True):
        # log_info(f'dumping {f}')
        lines = []
        if type(f) is Function:
            f = [f]
        if type(f) is not list:
            try:
                next(f)
            except:
                try:
                    for b in f:
                        break
                except:
                    f = [f]
        for b in tqdm(f, alert=alert):
            lines += dump_il(b, il, filter)
        if lines:
            log_info('\n'.join(lines))
            log_warn(f'{len(lines)} lines')
    return _dump_il_func(f, il, alert, filter)
