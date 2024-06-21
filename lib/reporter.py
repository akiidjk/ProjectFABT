import datetime
import os
from pathlib import Path

from lib.logger import logging


class Reporter:

    def __init__(self, binary_name):
        name_report = f"report_{datetime.datetime.now().strftime('%d-%m-%y-%H-%M')}.md"
        logging.debug(name_report)
        path_report = os.path.join(Path(__file__).resolve().parent, "..", "reports")

        if not os.path.exists(path_report):
            os.mkdir(path_report)

        path = os.path.join(path_report, name_report)
        self.report = open(path, "w")
        self.init_report(binary_name)

    def init_report(self, binary_name):
        binary_name = os.path.basename(binary_name)
        try:
            self.write(
                f"# Report for {binary_name} | Date: {datetime.datetime.now().strftime('%d/%m/%y | Time:  %H-%M-%S')}\n")
        except IOError as error:
            logging.error(f"Error in the init of report: {error}")

    def write(self, content):
        self.report.write(content)
