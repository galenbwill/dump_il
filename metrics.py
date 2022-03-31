
# 
# https://dev.to/ahmedeltaweel/python-decorator-to-show-execution-time-of-a-function-afk
#

from datetime import timedelta
from functools import wraps
from timeit import default_timer as timer
from typing import Any, Callable, Optional

import binaryninja as bn

import logging


class BNHandler(logging.Handler):
    emitters = {
        logging.CRITICAL: bn.log_alert,
        logging.ERROR: bn.log_error,
        logging.WARN: bn.log_warn,
        logging.INFO: bn.log_info,
        logging.DEBUG: bn.log_debug,
    }

    def __init__(self, level=logging.NOTSET) -> None:
        super().__init__(level)
        self.setFormatter(logging.Formatter('%(name)s:%(levelname) 7s: %(asctime)s %(message)s'))

    def emit(self, record: logging.LogRecord):
        emitter = BNHandler.emitters[record.levelno]
        emitter(self.format(record))


# logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
# logging.basicConfig(format='%(name)s:%(levelname) 7s: %(asctime)s %(message)s', level=logging.INFO)
logger = logging.getLogger('[METRICS]')
for h in list(logger.handlers):
    logger.removeHandler(h)
logger.addHandler(BNHandler())


def metrics(
    func: Optional[Callable] = None,
    name: Optional[str] = None,
    hms: Optional[bool] = False,
    alert: Optional[bool] = False,
    timeit: Optional[bool] = False,
) -> Any:
    """Decorator to show execution time.

    :param func: Decorated function
    :param name: Metrics name
    :param hms: Show as human-readable string
    """
    assert callable(func) or func is None

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not timeit:
                return fn(*args, **kwargs)
            comment = f"Execution time of {name or fn.__name__}:"
            t = timer()
            result = fn(*args, **kwargs)
            te = timer() - t

            # Log metrics
            # logger = logging.getLogger('[METRICS]')
            if hms and te >= 60.0:
                # logger.error(f"e {comment} {timedelta(seconds=te)}")
                logger.warn(f"w {comment} {timedelta(seconds=te)}")
                # logger.info(f"{comment} {timedelta(seconds=te)}")
                if alert:
                    logger.critical(f"{comment} {timedelta(seconds=te)}")
            else:
                # logger.info(f"{comment} {te:>.6f} sec")
                logger.warn(f"{comment} {te:>.6f} sec")
                if alert:
                    logger.critical(f"{comment} {te:>.6f} sec")

            return result

        return wrapper

    return decorator(func) if callable(func) else decorator
