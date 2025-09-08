"""Setup script for the Digital Forensics Workbench.

This script assists with creating an isolated Python virtual
environment, installing the required dependencies and optionally
launching the application. It attempts to detect the host operating
system and prints hints for installing external forensic tools.

Example usage on Linux and Windows:

```
python install_dfw.py --venv-name dfw_env --run
```

The above command creates (or reuses) a virtual environment named
``dfw_env``, installs packages listed in ``requirements.txt`` and
starts the workbench. On subsequent runs you can simply activate
the environment and launch ``python -m dfw`` directly.
"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path


def detect_os() -> str:
    """Return a friendly name for the current operating system."""
    return platform.system()


def create_virtualenv(venv_dir: Path) -> None:
    """Create a virtual environment in the given directory if it does not already exist."""
    if venv_dir.exists():
        print(f"Using existing virtual environment at {venv_dir}")
        return
    print(f"Creating virtual environment at {venv_dir}…")
    subprocess.check_call([sys.executable, '-m', 'venv', str(venv_dir)])
    print("Virtual environment created.")


def install_requirements(venv_dir: Path, requirements_file: Path) -> None:
    """Install Python dependencies into the virtual environment using pip.

    This function first attempts to upgrade pip using the Python
    interpreter inside the virtual environment (``python -m pip``). If
    upgrading pip fails it will continue using the existing pip
    installation. Afterwards it installs the packages listed in
    ``requirements_file``.
    """
    os_type = detect_os()
    # Determine path to the Python interpreter inside the virtual environment.  We
    # intentionally rely on ``python -m pip`` for package management so
    # that pip is always invoked in a safe and supported manner.  A
    # separate pip executable is not used here to avoid the "cannot
    # modify pip by invoking pip directly" error on some platforms.
    python_exe = venv_dir / ('Scripts' if os_type == 'Windows' else 'bin') / ('python.exe' if os_type == 'Windows' else 'python')
    # Upgrade pip by invoking python -m pip.  This invocation avoids
    # self-modification issues when pip upgrades itself.  If the
    # upgrade fails we proceed with the existing version of pip.
    print(f"Upgrading pip in {venv_dir}…")
    try:
        subprocess.check_call([str(python_exe), '-m', 'pip', 'install', '--upgrade', 'pip'])
    except subprocess.CalledProcessError:
        print("Warning: Could not upgrade pip; continuing with the existing version.")
    # Install requirements using the same python interpreter.  We call
    # ``python -m pip install -r requirements.txt`` to ensure pip is
    # invoked correctly across all platforms (Windows, Linux, etc.).
    print(f"Installing dependencies from {requirements_file}…")
    subprocess.check_call([str(python_exe), '-m', 'pip', 'install', '-r', str(requirements_file)])
    print("Python dependencies installed.")


def launch_application(venv_dir: Path) -> None:
    """Launch the workbench from the virtual environment."""
    os_type = detect_os()
    python_exe = venv_dir / ('Scripts' if os_type == 'Windows' else 'bin') / ('python.exe' if os_type == 'Windows' else 'python')
    print("Starting Digital Forensics Workbench…")
    subprocess.check_call([str(python_exe), '-m', 'dfw'])


def print_external_tool_guidance() -> None:
    """Print hints on installing external forensic tools required for full functionality."""
    os_type = detect_os()
    print()
    print("==================== External Tools ====================")
    if os_type == 'Linux':
        print("On Linux you should install The Sleuth Kit (mmls), Wireshark/tshark, Volatility3 and ADB.")
        print("For example on Debian/Ubuntu:")
        print("  sudo apt update")
        print("  sudo apt install sleuthkit python3-pytsk3 wireshark tshark adb")
        print("  pip install volatility3")
    elif os_type == 'Windows':
        print("On Windows install the required tools using Chocolatey, Scoop or the official installers.")
        print("Ensure that the following are on your PATH:")
        print("  - The Sleuth Kit (mmls)")
        print("  - Wireshark/tshark")
        print("  - Volatility3 (pip install volatility3)")
        print("  - ADB (from Android SDK Platform Tools)")
        print()
        print("Optional: pytsk3 (Python binding for The Sleuth Kit) can be installed to enable extraction of files ")
        print("from disk images on Windows. However prebuilt wheels are not available for all Python versions")
        print("and building from source requires the Microsoft Visual C++ Build Tools. If you need this")
        print("functionality you can install the C++ build tools and then run 'pip install pytsk3' inside")
        print("your virtual environment. Without pytsk3, you can still mount disk images on Linux or use")
        print("other operating systems to perform the extraction.")
    else:
        print("Please install forensic tools appropriate for your OS (Sleuth Kit, Volatility3, Wireshark/tshark and ADB).")
    print("========================================================")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Set up and launch the Digital Forensics Workbench.")
    parser.add_argument('--venv-name', default='dfw_env', help="Directory name for the virtual environment (default: dfw_env)")
    parser.add_argument('--no-install', action='store_true', help="Skip dependency installation (use existing venv)")
    parser.add_argument('--run', action='store_true', help="Launch the application after setup")
    args = parser.parse_args()

    os_type = detect_os()
    print(f"Detected operating system: {os_type}")
    venv_dir = Path(args.venv_name).absolute()
    requirements_file = Path(__file__).with_name('requirements.txt')

    create_virtualenv(venv_dir)
    if not args.no_install:
        install_requirements(venv_dir, requirements_file)
    print_external_tool_guidance()
    if args.run:
        launch_application(venv_dir)


if __name__ == '__main__':
    main()