from binaryninjaui import UIContext

# from binaryninja import *

# from binaryninja.log import Logger

import binaryninja

import sys

__module__ = sys.modules[__name__]

__logger = binaryninja.Logger(0, __module__.__name__)

log = __logger.log
log_debug = __logger.log_debug
log_info = __logger.log_info
log_warn = __logger.log_warn
log_error = __logger.log_error
log_alert = __logger.log_alert

from .plugin import init

from .dump_il import interesting as interesting_instruction, dump_il_instr, dump_il, dump_il_func

init()