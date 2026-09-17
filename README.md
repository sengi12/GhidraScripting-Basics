# <a name="top"></a>GhidraScripting in a Nutshell

If you are just getting into scripting with [Ghidra](https://ghidra-sre.org), a great reference can be found at [GhidraSnippets](https://github.com/cetfor/GhidraSnippets) (Authored by [John Toterhi](https://github.com/cetfor)). This will act as a living document of my interpretation of the [GhidraAPI](https://ghidra.re/ghidra_docs/api/). 

> **Last verified against Ghidra 12.1.3** (released 2026-08-18). This guide was originally written in 2020 against Ghidra 9.1.2; every version-specific path and claim below has been re-checked against the 12.1.3 source tree. Ghidra 12.x needs **JDK 21** or newer to run and **Gradle 8.5+** to build anything, and it no longer ships with Jython turned on (see [Jython vs PyGhidra](#jython-vs-pyghidra)). If you are still on 9.x, the old text lives in this repo's git history.

## <a name="toc"></a>Table Of Contents

#### [Ghidra Script Basics](#basics) 

<details>
  <summary>An Introduction</summary>


- [`Scripting Languages`](#languages)
- [`Jython vs PyGhidra (2026)`](#jython-vs-pyghidra)
- [`Important Components`](#components)

</details>

<details>
  <summary>Development Tips</summary>


- [`Compiling External Extensions/Plugins`](#compiling-extensions)
- [`Where Ghidra Keeps Things`](#locations)
- [`Compiling Your GhidraScript for Testing`](#compilation)
- [`Automating Compilation in Ghidra for Testing`](#auto-compile)

</details>

#### [Ghidra Scripting Examples](#examples) 

<details>
  <summary>General</summary>



- [`Get the Current Program Name and Location on disk (Jython)`](#name-and-loc)
- [`Get the Current Program Name and Location on disk (PyGhidra)`](#name-and-loc-pyghidra)
- [`Export a Local Copy (Jython)`](#export)
- [`Export a Local Copy (PyGhidra)`](#export-pyghidra)

</details>

<details>
  <summary>Data Types</summary>



- [`Get DataType from Ghidra`](#getDataType)
- [`Create Custom DataType`](#custom-DT)

</details>

---

## <a name="basics"></a>Ghidra Script Basics

### An Introduction

The Ghidra API is your friend. For access within Ghidra, go to: "Help", and select "Ghidra API Help". This will take you to an interactive html page which provides everything you need to know in order to interact with the API. You can also go to this online version of the [GhidraAPI](https://ghidra.re/ghidra_docs/api/), or unzip the copy that ships with your install at `<GhidraInstallDir>/docs/GhidraAPI_javadoc.zip`.

> Note that all of the references I make to the Ghidra docs will be to `ghidra.re` which may not be up to date. When in doubt, the javadoc zip in your own install is always the right version.

### <a name="languages"></a>Scripting Languages

The Ghidra API allows scripting in 2 languages: (Note that the API works similarly with both of these languages)

- [Python](https://www.python.org) - in one of two flavors, [Jython](https://www.jython.org) (Python 2.7, legacy) or [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md) (CPython 3). See the [next section](#jython-vs-pyghidra) for which one you want.
- [Java](https://www.java.com/en/) 

In order for Ghidra scripts to work in Java, the file that is run must extend GhidraScript:

```java
import ghidra.app.script.GhidraScript;
public class MyClass extends GhidraScript { }
```

Python scripts don't extend anything. Ghidra hands the script `currentProgram`, `currentAddress`, `state`, `monitor` and friends as globals, and every method on [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) as a bare function. What a Python script *does* need is a header comment telling the Script Manager which interpreter to use:

```python
# A one-line description of the script goes first.
# @category Examples.Python
# @runtime PyGhidra     # or: @runtime Jython
```

Without the `@runtime` tag Ghidra picks whichever `.py` script provider it finds first, so always set it. The older Jython examples in this repo also start with `import ghidra.app.script.GhidraScript`; that line is harmless but not required.

[:arrow_up:Back to Top](#top)​ 

### <a name="jython-vs-pyghidra"></a>Jython vs PyGhidra (2026)

When this guide was written, "Python in Ghidra" meant Jython, a Python 2.7 running on the JVM, and it was on by default. That is no longer the situation:

- **PyGhidra** is the supported Python route. It is real CPython 3 (3.9 through 3.14 for Ghidra 12.1.3) talking to the JVM through [JPype](https://jpype.readthedocs.io/en/latest/), it ships inside Ghidra under `Ghidra/Features/PyGhidra`, and both the GUI and headless Ghidra can run GhidraScripts written in it. You get f-strings, type hints, `pip`, and every third-party module you already use.
- **Jython** still exists but is an *Extension* now, is still Python 2.7, and the Ghidra team calls it legacy. Ghidra's own release notes tell you to either install the extension, port your scripts to PyGhidra, or port them to Java.

**Running Jython scripts (legacy).** In the Ghidra project window (the "Front End") go to **File -> Install Extensions**, tick **Jython**, and restart Ghidra. After that, `.py` scripts tagged `# @runtime Jython` run from the Script Manager as before, and **Window -> Jython** in the CodeBrowser opens the interactive shell (it used to be called "Python" in 9.x).

**Running PyGhidra scripts.** Ghidra has to be *launched* in PyGhidra mode, which means starting it from a Python environment:

```bash
cd <GhidraInstallDir>/support
./pyghidraRun          # pyghidraRun.bat on Windows
```

The first run offers to `pip install` the bundled `pyghidra` module for you (a virtual environment is fine). From then on `.py` scripts tagged `# @runtime PyGhidra` run from the Script Manager, and **Window -> PyGhidra** opens a CPython 3 REPL with `currentProgram` and the rest already in scope. If you launch Ghidra with plain `ghidraRun`, PyGhidra scripts show up in the Script Manager but refuse to run.

**PyGhidra outside the GUI.** The same module works as a normal Python library, which is the nicest part:

```bash
pip install pyghidra
pip install ghidra-stubs==12.1.3   # optional, editor completion for the Ghidra API
export GHIDRA_INSTALL_DIR=/home/user/bin/ghidra/ghidra_12.1.3_PUBLIC   # optional, else the last-used install
```

```python
import pyghidra
with pyghidra.open_program("some_binary") as flat_api:
    program = flat_api.getCurrentProgram()
    print(program.getName(), program.getExecutablePath())
```

**Porting notes.** Most Jython scripts move over with the usual Python 2 to 3 fixes (`print` is a function, strings are unicode). The one JPype-specific wrinkle is that Java arrays are built with `jpype.JArray(jpype.JByte)(n)` instead of being conjured out of a Python list; Ghidra's own `Ghidra/Features/PyGhidra/ghidra_scripts/PyGhidraBasics.py` walks through it. Both example scripts in this repo have a [PyGhidra port](#name-and-loc-pyghidra) beside the Jython original.

[:arrow_up:Back to Top](#top) 

### <a name="components"></a>Important Components

There are two components of the [GhidraAPI](https://ghidra.re/ghidra_docs/api/) that are the most important to understand when writing GhidraScripts. 

- [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) 
- [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) 

The main reasons being that when writing GhdiraScripts, you can call all the functions within these two classes without any additional imports.

[:arrow_up:Back to Top](#top) 

---

### Development Tips

Below are some tips on how you could get started developing your own GhidraScript projects.

### <a name="compiling-extensions"></a>Compiling External Extension/Plugins

Ghidra is a very extensible tool and offers a lot of room to grow with external tools. Sometimes, the repository you grab from will be without the most up to date version of Ghidra which could cause some issues if that's what you're using. In order to compile these yourself, simply run the following script in the "external tool's" root directory (the directory with the `build.gradle` file):

```bash
gradle -PGHIDRA_INSTALL_DIR=/home/user/bin/ghidra/ghidra_12.1.3_PUBLIC
```

> Be sure to replace `/home/user/bin/ghidra/ghidra_12.1.3_PUBLIC` with the root folder of your specific Ghidra installation. Ghidra 12.x wants JDK 21+ and Gradle 8.5+ for this; a `gradle.properties` or `build.gradle` still expecting Java 17 is the usual reason an older extension refuses to build.

If you would rather have an IDE do this for you, Ghidra ships the **GhidraDev** Eclipse plugin under `<GhidraInstallDir>/Extensions/Eclipse/GhidraDev/` ([README](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraBuild/EclipsePlugins/GhidraDev/GhidraDevPlugin/README.md)), and since 11.2 the project window has **Tools -> Create VSCode Module Project...** which lays down a Visual Studio Code project with debug launchers and a `ghidra/distributeExtension` Gradle task already wired up.

[:arrow_up:Back to Top](#top) 

### <a name="locations"></a>Where Ghidra Keeps Things

Two directories matter for scripting, and both moved since 9.x:

- **Your scripts.** `~/ghidra_scripts` is the default user script directory; the Script Manager's **Manage Script Directories** toolbar button adds more. This is where you point it at a clone of this repo.
- **The user settings directory**, which holds tool state *and* the compiled-script cache described in the [next section](#compilation). Since Ghidra 11.1 it follows the platform convention:

| OS | User settings directory |
| --- | --- |
| Linux | `~/.config/ghidra/ghidra_12.1.3_PUBLIC/` (honors `$XDG_CONFIG_HOME`) |
| macOS | `~/Library/ghidra/ghidra_12.1.3_PUBLIC/` |
| Windows | `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\` |

Ghidra 9.2 through 11.0 used `~/.ghidra/.ghidra_<version>_PUBLIC/` on every OS, and 9.1.x and earlier is where this guide's original `~/.ghidra/.ghidra_9.1.2_PUBLIC/dev/ghidra_scripts/bin/` path came from. That `bin` directory does not exist anymore.

[:arrow_up:Back to Top](#top) 

### <a name="compilation"></a>Compiling Your GhidraScript for Testing

When this guide was first written, Ghidra Scripts were <u>**not**</u> automatically recompiled at runtime, and you had to delete the `.class` files out of a `bin` directory by hand (or with the `cleanup` script that used to live in this repo) to see your changes. **Ghidra 9.2 fixed that.** Java scripts are now compiled into OSGi bundles, one per script directory, and Ghidra rebuilds the bundle on its own whenever a source file in that directory changes. Python scripts, Jython or PyGhidra, were never compiled in the first place; save the file and run it again.

The bundles live under the [user settings directory](#locations):

```txt
<user settings>/osgi/compiled-bundles/<hash of the source directory>/
```

You should not normally need to touch that cache. When something *does* go sideways (a half-written bundle after a crash, a script that keeps running last week's code), the replacement `cleanup.py` in this repo clears it:

```bash
python3 cleanup.py --dry-run    # show which bundles were built from this checkout
python3 cleanup.py              # remove them; Ghidra rebuilds on the next run
python3 cleanup.py --all        # remove every compiled bundle, whoever built it
python3 cleanup.py --felix      # also clear the Felix bundle cache next to it
python3 cleanup.py --settings-dir ~/.config/ghidra/ghidra_12.1.3_PUBLIC
```

It probes both the old `~/.ghidra` layout and the 11.1+ platform directories, and it decides a bundle is "ours" by looking for a `.class` file named after any `.java` file in this checkout, so nothing unrelated gets deleted unless you ask for `--all`. There is no `ghidra_bin_location.txt` to maintain anymore.

> If the Script Manager still shows a stale error after a rebuild, the **Bundle Manager** (the **Manage Script Directories** button in the Script Manager toolbar) lets you disable and re-enable a script directory, which forces a fresh build.

[:arrow_up:Back to Top](#top) 

### <a name="auto-compile"></a>Automating Compilation in Ghidra

This section used to carry a `writeBinLocation()` helper and a `GhidraProvider` class that subclassed `JavaScriptProvider` to find the `.class` file for the cleanup script. Both are gone: `JavaScriptProvider.getClassFile()` no longer exists in Ghidra 12.x, and with [automatic recompilation](#compilation) there is nothing left to automate. If you still have a project carrying that helper, delete it; the OSGi rebuild happens whether or not you ask for it.

[:arrow_up:Back to Top](#top) 

---

## <a name="examples"></a>Ghidra Scripting Examples

The Python examples below come in pairs. The first of each pair is the original **Jython** version (Python 2.7, needs the Jython extension in Ghidra 12.x); the second is the **PyGhidra** port (CPython 3, the supported route). They live in [`examples/`](examples/) and [`examples/pyghidra/`](examples/pyghidra/) respectively, ready to drop into your `ghidra_scripts` directory.

### General

### <a name="name-and-loc"></a>Get the current Program Name and Location on disk (Jython)

This is taken straight from [GhidraSnippets](https://github.com/cetfor/GhidraSnippets#working-with-programs), but I see it as a great way to get your feet wet with the Ghidra API features and usage. As mentioned before we have direct access to everything on [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html), leaving our first important component to use: `currentProgram`, which extends [Program](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html).

> Jython / legacy - file: [`examples/getGeneralInfo.py`](examples/getGeneralInfo.py)

```python
# @category Examples.Python
# @runtime Jython
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print("The currently loaded program is: '{}'".format(name))
print("Its location on disk is: '{}'".format(location))
```

[:arrow_up:Back to Top](#top) 

### <a name="name-and-loc-pyghidra"></a>Get the current Program Name and Location on disk (PyGhidra)

The same thing in CPython 3. `currentProgram` is already a global, so the `getState()` dance is not needed, and the `typing.TYPE_CHECKING` block is purely for your editor: with `ghidra-stubs` installed it gives you completion on every Ghidra name, and at runtime PyGhidra injects those names before the first line of your script executes.

> PyGhidra / CPython 3 - file: [`examples/pyghidra/getGeneralInfo.py`](examples/pyghidra/getGeneralInfo.py)

```python
# Print the current program's name and its location on disk.
# @category Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print(f"The currently loaded program is: '{name}'")
print(f"Its location on disk is: '{location}'")
```

[:arrow_up:Back to Top](#top) 

### <a name="export"></a>Export a Local Copy (Jython)

This is a useful tool to use if you are working with a [GhidraServer](https://www.ghidra-server.org) hosted off of someone else's machine as you generally wouldn't have a local copy of the file you're working with. Nonetheless this takes advantage of Ghidra's export functionality, and allows you to export the file you are working with to wherever you wish on disk. 

> This is also taking advantage of how Ghidra can utilize Jython: `java.io.File` and Swing's `JFileChooser` are imported like Python modules. PyGhidra does the same through JPype.

> Jython / legacy - file: [`examples/exportLocalCopy.py`](examples/exportLocalCopy.py)

```python
# Author: Michael Sengelmann
# @category Examples.Python
# @runtime Jython
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

[:arrow_up:Back to Top](#top) 

### <a name="export-pyghidra"></a>Export a Local Copy (PyGhidra)

Same logic, Python 3. The one behavioral change is that cancelling the directory chooser is handled instead of blowing up on a `None` file, which the Jython version would do. `BinaryExporter.export()` still takes `(File, DomainObject, AddressSetView, TaskMonitor)`, and `Memory` is an `AddressSetView`, so `currentProgram.getMemory()` is what we hand it.

> PyGhidra / CPython 3 - file: [`examples/pyghidra/exportLocalCopy.py`](examples/pyghidra/exportLocalCopy.py)

```python
# Export a local copy of the current program when it does not exist on disk.
# @author Michael Sengelmann
# @category Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

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
```

[:arrow_up:Back to Top](#top) 

---

### Data Types

### <a name="getDataType"></a>Get Data Type from Ghidra

This is an edited version of a example provided by Ghidra as an example of GhidraScripting in python and is a great template for getting started with more complicated scripts. Ghidra still ships it as `ChooseDataTypeScriptPy.py` (inside the Jython extension's `ghidra_scripts`).

> To view this in Ghidra go to: **Window**, and select **Jython** (with the Jython extension installed; it was **Python** back in 9.x). This will open up a new interactive [Jython](https://www.jython.org) shell. From here click <kbd>F1</kbd> and you will be shown a new help window with the below code shown.

```python
# @category Examples.Python
# @runtime Jython
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

The [DataTypeSelectionDialog](https://ghidra.re/ghidra_docs/api/ghidra/app/util/datatype/DataTypeSelectionDialog.html) constructor and `AllowedDataTypes.FIXED_LENGTH` are unchanged in 12.1.3, so this body runs as-is under PyGhidra too; just swap the header to `# @runtime PyGhidra`.

[:arrow_up:Back to Top](#top) 

### <a name="custom-DT"></a>Create Custom DataType



[:arrow_up:Back to Top](#top)

---

Licensed under the [Apache License 2.0](LICENSE). Copyright 2020-2026 Michael Sengelmann.
