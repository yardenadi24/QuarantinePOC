# EDR Quarantine Folder Proof of Concept

## Overview
This project is an EDR related POC implemanting Quarantine folder.
It focuses on a filesystem minifilter that manages access to a quarantine folder. The filter is designed to:
- **Block Directory Queries**: Prevents any attempts to query or list the contents of the quarantine directory.
- **Adjust Responses for Parent Directory Queries**: Removes entries related to the quarantine directory from any listings to ensure it remains unlisted.
- **Intercept File Operations**: Blocks attempts to open, modify, or delete the quarantine directory.

## Prerequisites
- A Windows operating system with administrative access.
- Visual Studio or another compatible compiler with support for the Windows Driver Kit (WDK).

## Installation Instructions

### Step 1: Compile the Driver
Compile the project using Visual Studio or your preferred IDE that supports Windows Driver Kit (WDK) development. Ensure that the target configuration matches your system architecture (x86, x64).

### Step 2: Deploy the Driver
After compilation, transfer the resulting `.sys` file (the driver) to your target machine. This could be a virtual machine or a dedicated test system.

### Step 3: Setup the Environment
On your target machine, create the directory that will be managed by the minifilter:
"C:\EdrPOC\Quarantine"

### Step 4: Load the Minifilter
Execute the following commands in an elevated Command Prompt on the target machine:
```cmd
sc create [Service name] type= filesys binPath= "[Path to the sys file]"
```
```cmd
fltmc load [Service name]
```

### Unloading the Minifilter
```cmd
fltmc unload [Service name]
```
