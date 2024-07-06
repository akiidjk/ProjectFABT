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

### Config

So for add command simple modify the config.json file and add in the list a map with this format

**Command config**

```json
{
  "command": "The command to be executed (e.g., 'strings').",
  "args": "One or more arguments for the command, with '{file}' as a placeholder for the file path.",
  "check": "An argument used to verify the correctly functioning of the command. (e.g., '-v or --version')"
}
```

Some example they are already in the file

**Logging config**

The possible value for the logging are: [DEBUG,INFO,WARNING,ERROR] i advice INFO

**Keywords config**

Simple add regex or word in the list of keywords

### Example Command

```sh
fabt -f /path/to/binary -d Ubuntu -s -k "keyword1 ^[0-9A-Fa-f]+$"
