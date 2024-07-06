import json
import logging
import os
import subprocess
from pathlib import Path
from sys import platform

DISTRO = "-d Ubuntu"  # TODO add argument


def remove_null_bytes(text):
    return text.replace('\x00', '')


def run_command(command, auto=True, distro="", timeout=None):
    if platform.startswith('win') and auto:
        command = f"wsl -d {distro} {command}" if distro != "" else f"wsl {command}"
    logging.debug(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out after {timeout} seconds")
        logging.warning(
            "If the command require an input you can type the input in the terminal normally and press enter to continue or run the command manually")
        process.kill()
        stdout, stderr = "", "Timeout error"

    return remove_null_bytes(stdout), remove_null_bytes(stderr)


def read_config():
    path = os.path.join(Path(__file__).resolve().parent, "..", "config.json")
    with open(path, 'r') as config_file:
        return json.load(config_file)


def copy(path_source, path_target):
    try:
        with open(path_source, 'r') as source:
            with open(path_target, 'w') as target:
                target.write(source.read())
    except IOError as error:
        logging.error(f"Error in copy: {error}")
        return 1


def fix_path(path, distro):
    results = run_command(f'wslpath "{path}"', distro=distro)
    logging.debug(f"Results: {results}")
    return results[0]


def find_word_positions(text, word_pattern):
    matches = []
    lines = text.splitlines()
    for line_num, line in enumerate(lines, start=1):
        for match in word_pattern.finditer(line):
            start_pos = match.start()
            end_pos = match.end()
            matches.append({
                'line': line_num,
                'start': start_pos,
                'end': end_pos,
                'matched_text': match.group()
            })
    logging.debug(f"Found {len(matches)} matches")
    return len(matches), matches
