import os.path
from pathlib import Path
from sys import platform

from lib.logger import logging
from lib.utils import run_command

# list_command = [
#     'strings',
#     # 'checksec',
#     'file',
#     'readelf'
# ]

commands = [
    {"command": "strings", "args": "{file}"},
    {"command": "file", "args": "{file}"},
    {"command": "objdump", "args": "-d {file}"},
]

DISTRO = "-d Ubuntu"  # TODO add argument
FILE = "hidden_variable"
PATH = Path(__file__).resolve().parent
FULL_PATH = os.path.join(PATH, "binary_test", FILE).strip()


def check_wsl():
    logging.info("Checking for WSL")
    results = run_command("wsl --list", auto=False)

    if results[1] != '':
        logging.error("The system not have WSL with some distribution or an error occurred: " + results[1])
        return 1

    list_distro = [element for element in results[0].strip().split('\n')[1:] if element != '']

    if len(list_distro) == 0:
        logging.error("The system has no WSL with some distribution or an error occurred: " + results[0])
        return 1

    logging.info("The system has a WSL with some distribution \n" + '\n'.join(list_distro))


def check_command():
    logging.info("Checking for command")

    for command in commands:

        results = run_command(f"{command['command']} -v")

        if results[1] != '' and results[0] == '':
            logging.error(f"The system not have the command: {command['command']} please install first: " + results[1])
            return 1

        logging.debug(f"Command: {command['command']} - Stdout: {results[0]} - Stderr: {results[1]}")
    return 0


def check():
    """This function check if the system has all the required dependencies"""
    global FULL_PATH
    if platform.startswith('win'):
        results = run_command(f'wslpath "{FULL_PATH}"')
        FULL_PATH = results[0]

        if check_wsl() == 1:
            return 1

    logging.info("System check passed")

    if check_command() == 1:
        return 1

    logging.info("Command check passed")

    return 0


def analysis():
    for command in commands:
        test = command['command'] + " " + command['args'].format(file=FULL_PATH)
        logging.debug(f"Test: {test}")
        results = run_command(test)

        logging.debug(f"Command: {command['command']} - Stdout: {results[0]} - Stderr: {results[1]}")


def main():
    logging.info("Starting check")
    if check() == 1:
        exit(1)
    logging.info("All checks passed")
    logging.info("Start analysis")
    analysis()


if __name__ == '__main__':
    main()
