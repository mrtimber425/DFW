"""Main entry point for the Digital Forensics Workbench.

This module simply calls the GUI launcher. It exists so that the
package can be started with ``python -m dfw`` from a command line or
through a direct script invocation.
"""

try:
    # Relative import when run as part of the dfw package (python -m dfw.main)
    from .gui import run_app
except ImportError:
    # Absolute import fallback to allow running as a script (python dfw/main.py)
    from dfw.gui import run_app  # type: ignore


def main() -> None:
    run_app()


if __name__ == '__main__':
    main()