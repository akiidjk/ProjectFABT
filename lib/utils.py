import logging
import subprocess
from sys import platform

DISTRO = "-d Ubuntu"  # TODO add argument


def remove_null_bytes(text):
    return text.replace('\x00', '')


def run_command(command, auto=True):
    if platform.startswith('win') and auto:
        command = f"wsl {DISTRO} {command}"
    logging.debug(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return remove_null_bytes(stdout), remove_null_bytes(stderr)
