"""Class for print the log."""
import logging

from colorama import Fore, Style, init

from lib.utils import read_config

LEVEL = read_config()["logging"].upper()


# LEVEL = logging.ERROR


# ---- This file make the preset for Log ----

class CustomFormatter(logging.Formatter):
    """Custom Formatter class to format the output of logger in a nice way!

    Args:
        logging (logging): The logging formatter

    """
    grey = Style.BRIGHT + Fore.LIGHTBLACK_EX
    yellow = Style.BRIGHT + Fore.YELLOW
    red = Fore.RED
    blue = Style.BRIGHT + Fore.BLUE
    green = Style.BRIGHT + Fore.GREEN
    black = Style.BRIGHT + Fore.BLACK
    bold_red = Style.BRIGHT + Fore.RED
    white = Style.BRIGHT + Fore.WHITE

    date = "%(asctime)s - "
    level_name = "%(levelname)s - "
    message = "%(message)s - "
    filename = "(%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: black + date + grey + level_name + white + message + green + filename,
        logging.INFO: black + date + blue + level_name + white + message + green + filename,
        logging.WARNING: black + date + yellow + level_name + white + message + green + filename,
        logging.ERROR: black + date + red + level_name + white + message + green + filename,
        logging.CRITICAL: black + date + bold_red + level_name + white + message + green + filename,
    }

    def format(self, record):
        """Format the message with custom colors and styles.

        Args:
            record (_type_): _description_

        Returns:
            str: The log formatted
        """
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# Initialize colorama
init(autoreset=True)

# Clear any existing handlers on the root logger
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# Set the logging level
level_num = logging.getLevelName(LEVEL)
logging.getLogger().setLevel(level_num)

handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter())
logging.getLogger().addHandler(handler)
