# Print the current program's name and its location on disk.
# PyGhidra (CPython 3) port of examples/getGeneralInfo.py.
# @author Michael Sengelmann
# @category Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    # Only for editor completion (pip install ghidra-stubs==<version>);
    # PyGhidra injects these names at runtime.
    from ghidra.ghidra_builtins import *

name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print(f"The currently loaded program is: '{name}'")
print(f"Its location on disk is: '{location}'")
