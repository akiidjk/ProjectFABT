import json
import logging
import subprocess
from sys import platform

DISTRO = "-d Ubuntu"  # TODO add argument


def remove_null_bytes(text):
    return text.replace('\x00', '')


def run_command(command, auto=True, distro=""):
    if platform.startswith('win') and auto:
        command = f"wsl -d {distro} {command}"
    logging.debug(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate()
    return remove_null_bytes(stdout), remove_null_bytes(stderr)


def read_config():
    with open("config.json", 'r') as config_file:
        return json.load(config_file)


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
