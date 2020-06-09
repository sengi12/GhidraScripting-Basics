# <a name="top"></a>GhidraScripting in a Nutshell

If you are just getting into scripting with [Ghidra](https://ghidra-sre.org), a great reference can be found at [GhidraSnippets](https://github.com/cetfor/GhidraSnippets) (Authored by [John Toterhi](https://github.com/cetfor)). This will act as a living document of my interpretation of the [GhidraAPI](ghidra.re/ghidra_docs/api/). 

## <a name="toc"></a>Table Of Contents

#### [Ghidra Script Basics](#basics) 

<details>
  <summary>An Introduction</summary>


- [`Scripting Languages`](#languages)
- [`Important Components`](#components)

</details>

<details>
  <summary>Development Tips</summary>


- [`Compiling External Extensions/Plugins`](#compiling-extensions)
- [`Compiling Your GhidraScript for Testing`](#compilation)
- [`Automating Compilation in Ghidra for Testing`](#auto-compile)

</details>

#### [Ghidra Scripting Examples](#examples) 

<details>
  <summary>General</summary>



- [`Get the Current Program Name and Location on disk`](#name-and-loc)
- [`Export a Local Copy`](#export)

</details>

<details>
  <summary>Data Types</summary>



- [`Get DataType from Ghidra`](#getDataType)
- [`Create Custom DataType`](#custom-DT)

</details>

---

## <a name="basics"></a>Ghidra Script Basics

### An Introduction

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

[:arrow_up:Back to Top](#top)​ 

### <a name="components"></a>Important Components

There are two components of the [GhidraAPI](ghidra.re/ghidra_docs/api/) that are the most important to understand when writing GhidraScripts. 

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
gradle -PGHIDRA_INSTALL_DIR=/home/user/bin/ghidra/ghidra_9.1.2_PUBLIC
```

> Be sure to replace `/home/user/bin/ghidra_9.1.2_PUBLIC` with the root folder of your specific Ghidra installation.

### <a name="compilation"></a>Compiling Your GhidraScript for Testing

Ghidra Scripts are <u>**not**</u> automatically recompiled at runtime. This means that in order for you to make sure your live changes actually get applied at runtime, you need to delete the related `.class` files that Ghidra generates at compilation. Ghidra stores these class files in a directory labeled `bin` located within the `/.ghidra/` directory (**<u>NOTICE</u>** the `.` at the beginning making it a hidden folder). I have found that a clean way to do this is with a python script, `cleanup`, which looks for a file within the same directory called `ghidra_bin_location.txt`. Our python script expects the `txt` file to contain a utf-8 encoding of your specific bin location where the `.class` files are generated. The python script then will delete every `.class` file within the directory that matches the structure of your project.  `ghidra_bin_location.txt` must exist and contain the ghidra bin folder location for it to work properly. 

Here is an <u>EXAMPLE</u> file location on a llinux system:

```txt
/home/user/.ghidra/.ghidra_9.1.2_PUBLIC/dev/ghidra_scripts/bin/
```

Here is the `cleanup` script:

```python
#!/usr/bin/env python
import os
import sys

GHIDRA_BIN_FILE = "ghidra_bin_location.txt"

dir = open(GHIDRA_BIN_FILE, "rb")
dir_str = dir.read().decode("utf-8").rstrip("\n\r")
pwd = os.path.dirname(os.path.realpath(__file__))
if(len(dir_str) < 1) :
    print("empty string in file")
    exit(0)
files = []
p = os.listdir(pwd)
for item in p:
    if(item.endswith(".java")):
        files.append(str(item[:-5]))
o = os.listdir(dir_str)
for item in o:
    if(item.endswith(".class") and item[:-6] in files):
        os.remove(dir_str + item)
        print("deleted: "+item)
```

> Notice that this will only look for files in your projects root directory. In order for this to work with a nested directory structure, you will have to modify it.

### <a name="auto-compile"></a>Automating Compilation in Ghidra

For this to work autonomously, I wrote a function you can add to your MAIN ghidra class which will use the Ghidra API to create this file with the correct location for you.

```java
public void writeBinLocation(String NameOfFile){ // run python cleanup.py to recompile program
    GhidraProvider mp = new GhidraProvider();
	String path = mp.getClass(sourceFile, NameOfFile).getAbsolutePath();
	path = path.substring(0, path.length()-16);
	String fileName = currentDirectory+"ghidra_bin_location.txt";
	try{
		OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileName), StandardCharsets.UTF_8);
		writer.write(path);
		writer.close();
  	}catch(IOException e){}
}
```

For this to work, you'll need to create the following class `GhidraProvider.java` which extends Ghidra's `JavaScriptProvider`:

```java
import ghidra.app.script.JavaScriptProvider;
import generic.jar.ResourceFile;
import java.io.File;

public class GhidraProvider extends JavaScriptProvider {
    public GhidraProvider(){
        super();
    }
    public File getClass(ResourceFile sourceFile, String className){
        return getClassFile(sourceFile, className);
        }
}
```

There may be a better way to do this, but it works so I haven't messed with it.

[:arrow_up:Back to Top](#top) 

---

## <a name="examples"></a>Ghidra Scripting Examples

### General

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

[:arrow_up:Back to Top](#top) 

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

[:arrow_up:Back to Top](#top) 

---

### Data Types

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

[:arrow_up:Back to Top](#top) 

### <a name="custom-DT"></a>Create Custom DataType



[:arrow_up:Back to Top](#top) 