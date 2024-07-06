# FABT | Fast Analysis Binary Tool

A tool for executing binaries and searching keywords or regex in stdout, created for CTF.

## Description

FABT (Fast Analysis Binary Tool) is designed to help with the execution of binary files and the subsequent analysis of
their output. This tool is particularly useful for Capture The Flag (CTF) competitions where quick and efficient binary
analysis can be crucial.

With FABT, users can specify binaries to execute, distributions for WSL, and search for specific keywords or regular
expressions within the output. It can be configured via the command line or a `config.json` file.

## Requirements

- Linux/Windows
- python3
- colorama installed with ```pip install colorama```

## Installation

Simple run the ```setup.sh``` if you are on linux or ```setup.ps1``` if you are on windows (for sure remember to run as
admin)

## Usage

### Command Line Arguments

- **`-f` or `--filepath`**:
    - Description: Path to the binary for execution.
    - Default: `None`

- **`-d` or `--distro`**:
    - Description: Specify the WSL distribution.
    - Default: `""` (empty string)

- **`-v` or `--version`**:
    - Description: Print the version and exit.

- **`-s` or `--search`**:
    - Description: Enable search in stdout for keywords or regex specified via command line or `config.json`.

- **`-k` or `--keywords`**:
    - Description: Specify keywords or regex (e.g., `^[0-9A-Fa-f]+$`) for searching in stdout. Separate multiple entries
      with a single space. Can be specified via command line or `config.json`.
    - Default: `None`

- **`-i` or `--init-main`**:
    - Generate a Python file named `main.py` that includes a template designed for leveraging `pwntools` to facilitate
      binary exploitation tasks. For insert a personal template edit the file /lib/template.py

### Config

So for add command simple modify the config.json file and add in the list a map with this format

**Command config**

```json
{
  "command": "The command to be executed (e.g., 'strings').",
  "args": "One or more arguments for the command, with '{file}' as a placeholder for the file path.",
  "check": "An argument used to verify the correctly functioning of the command. (e.g., '-v or --version')"
  "timeout": "*OPTIONAL* The maximum time in seconds for the command to execute."
}
```

Some example they are already in the file

**Logging config**

The possible value for the logging are: [DEBUG,INFO,WARNING,ERROR] i advice INFO

**Keywords config**

Simple add regex or word in the list of keywords

**The standard template file (template.py)**

```python

# !/usr/bin/env python3
from sys import argv

from pwn import *

host = "127.0.0.1"
port = 1337
elf = ELF("./binary")

# context.arch = 'amd64'
context.terminal = ['mate-terminal', '-x', 'sh', '-c']
context.level = 'info'


def main(mode: str):
    if mode == "local":
        p = elf.process()
        g = gdb.attach(p, gdbscript='''''')
    elif mode == "remote":
        p = connect(host, port)
    else:
        Error("Usage: python3 exploit.py [local|remote]")
        exit(1)

    p.interactive()


if __name__ == "__main__":
    main(argv[1])

# Good luck by @akiidjk


```

## Notes:

FABT uses subprocess.Popen and when using a command such as strace or ltrace, it can request an input that can be given
with a simple text when execution appears to be blocked

### Example Command

```sh
fabt -f /path/to/binary -d Ubuntu -s -k "keyword1 ^[0-9A-Fa-f]+$" -i
