# Print the current program's name and its location on disk.
# Jython (Python 2.7) version - legacy. Ghidra 12.x only runs this after you
# install the "Jython" extension (File -> Install Extensions). See
# examples/pyghidra/getGeneralInfo.py for the CPython 3 port.
# @category Examples.Python
# @runtime Jython
import ghidra.app.script.GhidraScript
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print("The currently loaded program is: '{}'".format(name))
print("Its location on disk is: '{}'".format(location))
