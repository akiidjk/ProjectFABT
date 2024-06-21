import json
import logging
import subprocess
from sys import platform

DISTRO = "-d Ubuntu"  # TODO add argument


def remove_null_bytes(text):
    return text.replace('\x00', '')


def run_command(command, auto=True, distro=""):
    if platform.startswith('win') and auto:
        command = f"wsl {distro} {command}"
    logging.debug(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return remove_null_bytes(stdout), remove_null_bytes(stderr)


def read_command_config():
    with open("commands.json", 'r') as commands_file:
        return json.load(commands_file)['commands']


def write_result(command, result):
    with open("report.md", 'w') as report:
        report.write(f"## {command}")


def fix_path(path):
    results = run_command(f'wslpath "{path}"')
    return results[0]
