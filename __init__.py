from binaryninjaui import UIContext

from binaryninja import *

from .dump_il import dump_il_func, get_il


def dump(bv, start: Optional[int] = None, end: Optional[int] = None, il='hlil', filter=True):

    ac = UIContext.activeContext()
    vf = ac.getCurrentViewFrame()
    current_address = vf.getCurrentOffset()
    s, e = vf.getSelectionOffsets()
    start = start or s
    end = end or e
    log_info(f'({start:#x}, {end:#x})')
    current_functions = bv.get_functions_containing(current_address)
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

def dump_mlil(bv):
    dump(bv, il='mlil')

def dump_hlil(bv):
    dump(bv, il='hlil')

def dump_llil(bv):
    dump(bv, il='llil')

def dump_lifted_il(bv):
    dump(bv, il='lifted_il')

def dump_mlil_unfiltered(bv):
    dump(bv, il='mlil', filter=False)

def dump_hlil_unfiltered(bv):
    dump(bv, il='hlil', filter=False)

def dump_llil_unfiltered(bv):
    dump(bv, il='llil', filter=False)

def dump_lifted_il_unfiltered(bv):
    dump(bv, il='lifted_il', filter=False)

def dump_mlil_ssa_unfiltered(bv):
    dump(bv, il='mlil_ssa', filter=False)

def dump_hlil_ssa_unfiltered(bv):
    dump(bv, il='hlil_ssa', filter=False)

def dump_llil_ssa_unfiltered(bv):
    dump(bv, il='llil_ssa', filter=False)

# PluginCommand.register('filtered_il_dump', 'Dump IL filtered', main)
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
