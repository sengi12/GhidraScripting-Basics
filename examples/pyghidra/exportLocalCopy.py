# Export a local copy of the current program when it does not exist on disk
# (for example when it lives on a Ghidra Server).
# PyGhidra (CPython 3) port of examples/exportLocalCopy.py.
# @author Michael Sengelmann
# @category Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    # Only for editor completion (pip install ghidra-stubs==<version>);
    # PyGhidra injects these names at runtime.
    from ghidra.ghidra_builtins import *

# Java classes import like Python modules under JPype.
from java.io import File
from javax.swing import JFileChooser
from ghidra.app.util.exporter import BinaryExporter

name = currentProgram.getName()
program_file = getProgramFile()

if program_file is None:
    print("File doesn't exist locally.")
    chooser = JFileChooser()
    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
    chooser.setDialogTitle(f"Export {name} to...")
    chooser.showDialog(None, None)
    chosen_dir = chooser.getSelectedFile()
    if chosen_dir is None:
        print("No directory chosen; nothing exported.")
    else:
        out = File(chosen_dir, name)
        print(f"Creating {out.getAbsolutePath()}")
        exporter = BinaryExporter()
        exporter.export(out, currentProgram, currentProgram.getMemory(), getMonitor())
else:
    print(f"File already exists at {program_file.getAbsolutePath()}")
