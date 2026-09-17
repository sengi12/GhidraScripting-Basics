# Author: Michael Sengelmann
# Export a local copy of the current program when it does not exist on disk
# (for example when it lives on a Ghidra Server).
# Jython (Python 2.7) version - legacy. Ghidra 12.x only runs this after you
# install the "Jython" extension (File -> Install Extensions). See
# examples/pyghidra/exportLocalCopy.py for the CPython 3 port.
# @category Examples.Python
# @runtime Jython
import ghidra.app.script.GhidraScript

state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
# print("The currently loaded program is: '{}'".format(name))
# print("Its location on disk is: '{}'".format(location))
if(getProgramFile() is None):
    print("File doesn't exist locally.")
    from java.io import File
    from javax.swing import JFileChooser
    chooser = JFileChooser()
    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
    chooser.setDialogTitle("Export "+name+" to...")
    chooser.showDialog(None, None)
    path = chooser.getSelectedFile().getAbsolutePath()
    fullpath = path+"/"+name
    f = File(fullpath)
    print("Creating "+f.getAbsolutePath())
    from ghidra.app.util.exporter import BinaryExporter
    bexp = BinaryExporter()
    memory = currentProgram.getMemory()
    monitor = getMonitor()
    domainObj = currentProgram
    bexp.export(f, domainObj, memory, monitor)
else:
    print("File already exists at "+getProgramFile().getAbsolutePath())
