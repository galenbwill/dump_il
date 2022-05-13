# filtered_il_dump
Author: [**@galenbwill**](https://github.com/galenbwill)

_Dump IL filtered_

## Description:

Run one of the "Dump *" actions, and it will dump either the current line, the current selection, or if the cursor is at the beginning of a function, the entire function.

("Dump * filtered" means it will only dump "interesting instructions", which are currently defined to be floating point instructions or calls to intrinsics that take floating point scalar or numeric (integer or floating point) vector inputs. In the case of HLIL, an instruction is interesting if any of its descendants (operator or operands) is interesting. You could also define you own notion of interesting by modifying the functions (`interesting*`) in `dump_il.py`)

You can also `import filtered_il_dump` in the console and invoke `dump_il`, `dump_il_func`, and `dump_il_instr` directly.

https://github.com/galenbwill/dump_il

TODO:

- Make inclusion of IL in dump optional (maybe controlled with a setting)
- Move plugin actions to a menu
- Documentation of functions in `dump_il`
- Make a better name
- Release for inclusion in Binary Ninja Plugin Manager
## Minimum Version

3400

## License

This plugin is released under an [MIT license](./LICENSE).

## Metadata Version

2