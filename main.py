"""NeoXtractor IDX entrypoint"""

from core.args import arguments, parse_args
from core.logger import setup_logger
from gui import run as run_gui

def run_cli():
    """Run NeoXtractor IDX as a CLI application."""
    raise NotImplementedError("CLI mode is not implemented yet.")

if __name__ == "__main__":
    parse_args()
    setup_logger()
    if arguments.subcommand == "gui" or arguments.subcommand is None:
        run_gui()
