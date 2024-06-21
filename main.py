import argparse
import os
from sys import platform

from lib.logger import logging
from lib.reporter import Reporter
from lib.utils import run_command, read_command_config, fix_path


class FABT:
    def __init__(self, path, distro=""):
        self.path = path
        self.commands = read_command_config()
        self.reporter = None
        self.distro = distro

    def main(self):
        logging.info("Starting check")
        logging.debug(f"{self.commands = }")

        if self.check() == 1:
            exit(1)
        logging.info("All checks passed")
        logging.info("Initializing report")
        self.reporter = Reporter(self.path)

        logging.info("Start analysis")
        self.analysis()
        logging.info("Analysis completed")

    def check_wsl(self):
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

    def check_command(self):
        logging.info("Checking for command")

        for command in self.commands:

            results = run_command(f"{command['command']} {command['check']}")

            if results[1] != '' and results[0] == '':
                logging.error(
                    f"The system not have the command: {command['command']} please install first | Error: " + results[
                        1])
                return 1

            logging.debug(f"Command: {command['command']} - Stdout: {results[0]} - Stderr: {results[1]}")
        return 0

    def check(self):
        """This function check if the system has all the required dependencies"""

        logging.info("Check if the file exist")
        if not os.path.exists(self.path):
            logging.error("The file not exists")
            return 1

        if platform.startswith('win'):
            self.path = fix_path(self.path)

            if self.check_wsl() == 1:
                return 1

        logging.info("System check passed")

        if self.check_command() == 1:
            return 1

        logging.info("Command check passed")

        return 0

    def analysis(self):
        for command in self.commands:
            formatted_command = command['command'] + " " + command['args'].format(file=self.path)
            logging.debug(f"{formatted_command = }", self.distro)
            results = run_command(formatted_command)

            command_report = f"""
## Command: {command['command']}

### Stdout:
```
{results[0]}
```
### Stderror:

{results[1] if results[1] != '' else "No error occurred"}
"""

            self.reporter.write(command_report)

            logging.debug(f"Command: {command['command']} - Stdout: {results[0]} - Stderr: {results[1]}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='FABT | Fast Analysis Binary Tool',
        description='Make fast static analysis of a binary file for CTF format',
        epilog='For help or docs go to https://github.com/akiidjk/ProjectFABT')

    parser.add_argument("-f", "--filepath", default="No specified",
                        help="The path for the binary for the execution (absolute path required)")
    parser.add_argument("-d", "--distro", default="", help="Specify the distro for WSL")
    parser.add_argument("-v", "--version", help="Print the version", action='store_true')
    args = parser.parse_args()

    if args.version:
        print("Version: 1.0.0")
        exit(0)
    elif args.filepath == "No specified":
        logging.error("You must to specify the path of file")
        exit(1)

    fabt = FABT(args.filepath, distro=args.distro)
    fabt.main()
