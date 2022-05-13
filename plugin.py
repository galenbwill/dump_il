from binaryninjaui import UIContext

from binaryninja import *

from . import log, log_debug, log_info, log_warn, log_error, log_alert

from .dump_il import dump_il_func, get_il

def dump(bv, start: Optional[int] = None, end: Optional[int] = None, il='hlil', filter=True):

    ac = UIContext.activeContext()
    vf = ac.getCurrentViewFrame()
    current_address = vf.getCurrentOffset()
    s, e = vf.getSelectionOffsets()
    start = start or s or current_address
    end = end or e
    log_info(f'({start:#x}, {end:#x})')
    current_functions = bv.get_functions_containing(start)
    if current_functions:
        current_function = current_functions[0]
        log_info(str(current_function))
        current_il = get_il(current_function, il)
        # log_info(repr(type(current_il)))
        # current_instructions = [i for i in current_il.instructions if i.address in range(start, end)]
        current_instructions = [i for i in current_il.instructions if start <= i.address < end]
        log_info(f'len(current_instructions): {len(current_instructions)}')
        if len(current_instructions) <= 1:
            dump_il_func(current_function, il, alert=False, timeit=False, filter=filter)
        else:
            dump_il_func(current_instructions, il, alert=False, timeit=False, filter=filter)
    # dump_il_func(current_function)

def dump_mlil(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='mlil')

def dump_hlil(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='hlil')

def dump_llil(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='llil')

def dump_lifted_il(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='lifted_il')

def dump_mlil_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='mlil', filter=False)

def dump_hlil_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='hlil', filter=False)

def dump_llil_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='llil', filter=False)

def dump_lifted_il_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='lifted_il', filter=False)

def dump_mlil_ssa_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='mlil_ssa', filter=False)

def dump_hlil_ssa_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='hlil_ssa', filter=False)

def dump_llil_ssa_unfiltered(bv: BinaryView, start: Optional[int] = None, end: Optional[int] = None):
    dump(bv, start, end, il='llil_ssa', filter=False)

# PluginCommand.register('filtered_il_dump', 'Dump IL filtered', main)

def init():
    PluginCommand.register('Dump HLIL filtered', 'Display filtered HLIL instructions in the current function or selection', dump_hlil)
    PluginCommand.register('Dump MLIL filtered', 'Display filtered MLIL instructions in the current function or selection', dump_mlil)
    PluginCommand.register('Dump LLIL filtered', 'Display filtered LLIL instructions in the current function or selection', dump_llil)
    PluginCommand.register('Dump Lifted IL filtered', 'Display filtered Lifted IL instructions in the current function or selection', dump_lifted_il)

    PluginCommand.register('Dump HLIL', 'Display HLIL instructions in the current function or selection', dump_hlil_unfiltered)
    PluginCommand.register('Dump MLIL', 'Display MLIL instructions in the current function or selection', dump_mlil_unfiltered)
    PluginCommand.register('Dump LLIL', 'Display LLIL instructions in the current function or selection', dump_llil_unfiltered)
    PluginCommand.register('Dump Lifted IL', 'Display Lifted IL instructions in the current function or selection', dump_lifted_il_unfiltered)

    PluginCommand.register('Dump HLIL SSA', 'Display HLIL SSA instructions in the current function or selection', dump_hlil_ssa_unfiltered)
    PluginCommand.register('Dump MLIL SSA', 'Display MLIL SSA instructions in the current function or selection', dump_mlil_ssa_unfiltered)
    PluginCommand.register('Dump LLIL SSA', 'Display LLIL SSA instructions in the current function or selection', dump_llil_ssa_unfiltered)
