#!/usr/bin/env python3

import argparse
import os
import re
from sys import platform

import colorama

from lib.logger import logging
from lib.reporter import Reporter
from lib.utils import run_command, read_config, fix_path, find_word_positions


class FABT:
    def __init__(self, path_target, distro=""):
        self.path_target = path_target
        self.commands = read_config()['commands']
        self.reporter = None
        self.distro = distro
        self.stdouts = []

    def main(self):
        logging.info("Starting check")
        logging.debug(f"{self.commands = }")

        if self.check() == 1:
            exit(1)
        logging.info("All checks passed")
        logging.info("Initializing report")
        self.reporter = Reporter(self.path_target)

        logging.info("Start analysis")
        self.analysis()
        logging.info("Analysis completed")

    @staticmethod
    def check_wsl():
        logging.info("Checking for WSL")
        stdout, stderr = run_command("wsl --list", auto=False)

        if stderr != '':
            logging.error("The system not have WSL with some distribution or an error occurred: " + stderr)
            return 1

        list_distro = [element for element in stdout.strip().split('\n')[1:] if element != '']

        if len(list_distro) == 0:
            logging.error("The system has no WSL with some distribution or an error occurred: " + stdout)
            return 1

        logging.info("The system has a WSL with some distribution \n" + '\n'.join(list_distro))

    def check_command(self):
        logging.info("Checking for command")

        for command in self.commands:

            stdout, stderr = run_command(f"{command['command']} {command['check']}", distro=self.distro)

            if stderr != '' and stdout == '':
                logging.error(
                    f"The system not have the command: {command['command']} please install first | Error: " + stderr)
                return 1

            logging.debug(f"Command: {command['command']} - Stdout: {stdout} - Stderr: {stderr}")
        return 0

    def check(self):
        """This function check if the system has all the required dependencies"""

        logging.info("Check if the file exist")
        if not os.path.exists(self.path_target):
            logging.error("The file not exists")
            return 1

        if platform.startswith('win'):
            self.path_target = fix_path(self.path_target, self.distro)

            if self.check_wsl() == 1:
                return 1

        logging.info("System check passed")

        if self.check_command() == 1:
            return 1

        logging.info("Command check passed")

        return 0

    def analysis(self):
        for command in self.commands:
            logging.debug(f"Checking {command['command']}")
            logging.debug(command['args'].format(file=self.path_target))
            formatted_command = command['command'] + " " + command['args'].format(file=self.path_target)
            logging.debug(f"{formatted_command = }")
            stdout, stderr = run_command(formatted_command, distro=self.distro)

            command_report = f"""
## Command: {command['command']}

### Stdout:
```
{stdout}
```
### Stderror:

{stderr if stderr != '' else "No error occurred"}
"""
            self.stdouts.append((command['command'], stdout))
            self.reporter.write(command_report)

            logging.debug(f"Command: {command['command']} - Stdout: {stdout} - Stderr: {stderr}")

    def search(self, keywords: str):
        logging.info("Start research")
        self.reporter.write("## Keywords founded \n")

        if keywords:
            keywords = keywords.split(" ")
        else:
            keywords = read_config()["keywords"]

        logging.debug(keywords)

        for command, content in self.stdouts:
            for keyword in keywords:
                regex = re.compile(keyword) if keyword.startswith("^") else re.compile(
                    r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
                number_match, results = find_word_positions(content, regex)
                if number_match != 0:
                    keyword_report = f"### For command: {command} founded {number_match}\n"
                    logging.debug(f"For command: {command} founded {number_match}")
                    for match in results:
                        keyword_report += f"Found '{match['matched_text']}' at line {match['line']}, start: {match['start']}, end: {match['end']}\n\n"
                        logging.debug(
                            f"Found '{match['matched_text']}' at line {match['line']}, start: {match['start']}, end: {match['end']}")

                    keyword_report += (("-" * 40) + "\n")
                    logging.debug("-" * 40)
                    self.reporter.write(keyword_report)

        logging.info("Searched ended")
        return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='FABT | Fast Analysis Binary Tool',
        description='A tool for executing binaries and searching keywords or regex in stdout, created for CTF',
        epilog='For help or docs go to https://github.com/akiidjk/ProjectFABT')

    parser.add_argument("-f", "--filepath", default=None,
                        help="Path to the binary for execution ")
    parser.add_argument("-d", "--distro", default="", help="Specify the WSL distribution")
    parser.add_argument("-v", "--version", help="Print the version and exit", action='store_true')
    parser.add_argument("-s", "--search",
                        help="Enable search in stdout for keywords or regex specified via command line or config.json",
                        action='store_true')
    parser.add_argument("-k", "--keywords",
                        help="Specify keywords or regex (e.g., ^[0-9A-Fa-f]+$) for searching in stdout. Separate multiple entries with a single space. Can be specified via command line or config.json",
                        default=None)

    args = parser.parse_args()
    if args.version:
        print("Version: 1.0.0")
        exit(0)
    elif not args.filepath:
        logging.error("You must to specify the path of file")
        exit(1)

    fabt = FABT(os.path.abspath(args.filepath), distro=args.distro)
    fabt.main()

    if args.search:
        fabt.search(args.keywords)

    logging.info(
        f"FABT analysis finished you can found the report at {colorama.Fore.RED}{fabt.reporter.path}")
