# GhidraScripting in a Nutshell

If you are just getting into scripting with [Ghidra](https://ghidra-sre.org), a great reference can be found at [GhidraSnippets](https://github.com/cetfor/GhidraSnippets) (Authored by [John Toterhi](https://github.com/cetfor)). This will act as a living document of my interpretation of the [GhidraAPI](ghidra.re/ghidra_docs/api/). 

## Table Of Contents

<details>
  <summary>GhidraScript Basics</summary>

- [Scripting Languages](#languages)
- [Important Components](#components)

</details>

<details>
  <summary>Ghidra Scripting Examples</summary>
- [Get the current Program Name and Location on disk](#name-and-loc)
- [Export a Local Copy](#export)
- [Get DataType from Ghidra](#getDataType)

</details>

---

## <a name="basics"></a>GhidraScript Basics

The Ghidra API is your friend. For access within Ghidra, go to: "Help", and select "Ghidra API Help". This will take you to an interactive html page which provides everything you need to know in order to interact with the API. You can also go to this online version of the [GhidraAPI](ghidra.re/ghidra_docs/api/).

> Note that all of the references I make to the Ghidra docs will be to `ghidra.re` which may not be up to date. 

### <a name="languages"></a>Scripting Languages

The Ghidra API allows scripting in 2 languages: (Note that the API works similarly with both of these languages)

- [Python](https://www.python.org) 
- [Java](https://www.java.com/en/) 

In order for Ghidra scripts to work in Java, the file that is run must extend GhidraScript:

```java
import ghidra.app.script.GhidraScript;
public class MyClass extends GhidraScript { }
```

In order for Ghidra scripts to work in Python, the file that is run must import GhidraScript:

```python
import ghidra.app.script.GhidraScript
```

### <a name="components"></a>Important Components

There are two components of the [GhidraAPI](ghidra.re/ghidra_docs/api/) that are the most important to understand when writing GhidraScripts. 

- [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) 
- [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) 

The main reasons being that when writing GhdiraScripts, you can call all the functions within these two classes without any additional imports.

## <a name="examples"></a>Ghidra Scripting Examples

### <a name="name-and-loc"></a>Get the current Program Name and Location on disk

This is taken straight from [GhidraSnippets](https://github.com/cetfor/GhidraSnippets#working-with-programs), but I see it as a great way to get your feet wet with the Ghidra API features and usage. As mentioned before we have direct access to everything on [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html), leaving our first important component to use: `currentProgram`, which extends [Program](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html).

```python
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print("The currently loaded program is: '{}'".format(name))
print("Its location on disk is: '{}'".format(location))
```

### <a name="export"></a>Export a Local Copy

This is a useful tool to use if you are working with a [GhidraServer](https://www.ghidra-server.org) hosted off of someone else's machine as you generally wouldn't have a local copy of the file you're working with. Nonetheless this takes advantage of Ghidra's export functionality, and allows you to export the file you are working with to wherever you wish on disk. 

> This is also taking advantage of how Ghdira can utilize Jython.

```python
# Author: Michael Sengelmann
import ghidra.app.script.GhidraScript
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
```

This will check to see whether or not the file exists, and if it returns `null` (like in a ghidra-server) it will prompt the user for a location to export, and export the file to that location using Ghidra's [BinaryExporter](https://ghidra.re/ghidra_docs/api/ghidra/app/util/exporter/BinaryExporter.html).

### <a name="getDataType"></a>Get Data Type from Ghidra

This is an edited version of a example provided by Ghidra as an example of GhidraScripting in python and is a great template for getting started with more complicated scripts.

> To view this in Ghidra go to: **Window**, and select **Python**. This will open up a new interactive [Jython]() shell. From here click <kbd>F1</kbd> and you will be shown a new help window with the below code shown.

```python
import ghidra.app.script.GhidraScript
def getDataType():
    tool = state.getTool()
    dtm = currentProgram.getDataTypeManager()
    from ghidra.app.util.datatype import DataTypeSelectionDialog
    from ghidra.util.data.DataTypeParser import AllowedDataTypes
    selectionDialog = DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH)
    tool.showDialog(selectionDialog)
    dataType = selectionDialog.getUserChosenDataType()
    # if dataType != None: print("Chosen data type: " + str(dataType))
    if dataType != None: return dataType
```



