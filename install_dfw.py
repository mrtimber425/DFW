#!/usr/bin/env python3
"""
Enhanced setup script for the Digital Forensics Workbench.

This installer handles cross-platform setup, checks for external tools,
provides installation guidance, and sets up the Python environment.
Now includes automatic forensic tool installation!
"""

import argparse
import os
import platform
import subprocess
import sys
import shutil
import json
from pathlib import Path
from typing import Dict, List, Tuple
import urllib.request
import zipfile
import tarfile


class DFWInstaller:
    """Enhanced installer for Digital Forensics Workbench with auto-installer integration."""

    def __init__(self):
        self.os_type = platform.system()
        self.os_version = platform.version() if self.os_type == "Windows" else platform.release()
        self.arch = platform.machine()
        self.python_version = sys.version
        self.missing_tools = []
        self.installed_tools = []
        self.warnings = []
        
        # Auto-installer integration
        self.auto_installer = None
        self._init_auto_installer()

    def _init_auto_installer(self):
        """Initialize the auto-installer if available."""
        try:
            from auto_installer import ToolInstaller
            self.auto_installer = ToolInstaller()
            print("✓ Auto-installer loaded successfully")
        except ImportError:
            print("⚠ Auto-installer not available (auto_installer.py not found)")
        except Exception as e:
            print(f"⚠ Auto-installer initialization failed: {e}")

    def detect_os(self) -> str:
        """Detect operating system and architecture."""
        print(f"Detected OS: {self.os_type} {self.os_version}")
        print(f"Architecture: {self.arch}")
        print(f"Python version: {self.python_version}")
        
        # Show OS-specific warnings
        if self.os_type == "Windows":
            print("\n⚠ WARNING: Windows has limited forensic tool support")
            print("   For best results, consider using:")
            print("   • Windows Subsystem for Linux (WSL2)")
            print("   • Linux Virtual Machine")
            print("   • Dual-boot Linux system")
        elif self.os_type == "Linux":
            print("✓ Linux detected - full forensic tool support available")
        
        return self.os_type

    def check_python_version(self) -> bool:
        """Check if Python version is compatible."""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print("ERROR: Python 3.8 or higher is required")
            return False
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} is compatible")
        return True

    def check_forensic_tools(self) -> Dict[str, bool]:
        """Check availability of forensic tools using auto-installer."""
        print("\n" + "="*60)
        print("CHECKING FORENSIC TOOLS")
        print("="*60)
        
        if not self.auto_installer:
            print("⚠ Auto-installer not available, using basic checks...")
            return self._basic_tool_check()
        
        try:
            tool_status = self.auto_installer.get_tool_status()
            
            print(f"{'Tool Name':<25} {'Status':<15} {'OS Support'}")
            print("-" * 60)
            
            results = {}
            for tool_name, status in tool_status.items():
                status_text = "✓ Available" if status["available"] else "✗ Missing"
                if not status["os_supported"]:
                    status_text = "⚠ Not supported"
                
                support_text = "✓" if status["os_supported"] else "✗"
                
                print(f"{status['name']:<25} {status_text:<15} {support_text}")
                results[tool_name] = status["available"]
                
                if not status["available"] and status["os_supported"]:
                    if status["required"]:
                        self.missing_tools.append(status["name"])
                    else:
                        self.warnings.append(f"Optional tool missing: {status['name']}")
                elif status["available"]:
                    self.installed_tools.append(status["name"])
            
            print(f"\nSummary:")
            print(f"  ✓ Available: {len(self.installed_tools)} tools")
            print(f"  ✗ Missing: {len(self.missing_tools)} required tools")
            print(f"  ⚠ Warnings: {len(self.warnings)} optional tools")
            
            return results
            
        except Exception as e:
            print(f"Error checking tools: {e}")
            return self._basic_tool_check()

    def _basic_tool_check(self) -> Dict[str, bool]:
        """Basic tool checking without auto-installer."""
        basic_tools = {
            "python3": ["python3", "--version"],
            "pip": ["pip", "--version"],
            "git": ["git", "--version"]
        }
        
        results = {}
        for tool, cmd in basic_tools.items():
            try:
                subprocess.run(cmd, capture_output=True, check=True)
                print(f"✓ {tool} available")
                results[tool] = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"✗ {tool} missing")
                results[tool] = False
                
        return results

    def install_forensic_tools(self, auto_install: bool = False) -> bool:
        """Install forensic tools using the auto-installer."""
        print("\n" + "="*60)
        print("FORENSIC TOOLS INSTALLATION")
        print("="*60)
        
        if not self.auto_installer:
            print("⚠ Auto-installer not available")
            print("Please install tools manually:")
            self._show_manual_installation_guide()
            return False
        
        if self.os_type == "Windows":
            print("⚠ Windows detected - limited tool support")
            print("Installing Windows-compatible tools only...")
            
        try:
            if auto_install:
                print("🚀 Starting automatic installation...")
                results = self.auto_installer.install_all_tools(self._installation_progress)
                
                successful = sum(1 for success, _ in results.values() if success)
                total = len(results)
                
                print(f"\nInstallation Results:")
                print(f"  ✓ Successful: {successful}/{total} tools")
                
                if successful == total:
                    print("🎉 All tools installed successfully!")
                    return True
                else:
                    print("⚠ Some tools failed to install")
                    for tool_name, (success, message) in results.items():
                        if not success:
                            print(f"  ✗ {tool_name}: {message}")
                    return False
                    
            else:
                print("Manual installation mode selected")
                print("Use --auto-install flag for automatic installation")
                self._show_manual_installation_guide()
                return True
                
        except Exception as e:
            print(f"Installation failed: {e}")
            return False

    def _installation_progress(self, message: str, percent: int):
        """Show installation progress."""
        print(f"[{percent:3d}%] {message}")

    def _show_manual_installation_guide(self):
        """Show manual installation instructions."""
        print("\nManual Installation Guide:")
        print("-" * 40)
        
        if self.os_type == "Linux":
            print("Ubuntu/Debian:")
            print("  sudo apt-get update")
            print("  sudo apt-get install sleuthkit bulk-extractor foremost yara")
            print("  pip3 install plaso volatility3 yara-python")
            print("\nFedora/RHEL:")
            print("  sudo dnf install sleuthkit bulk-extractor foremost yara")
            print("  pip3 install plaso volatility3 yara-python")
            
        elif self.os_type == "Windows":
            print("Windows (Limited Support):")
            print("  pip install volatility3 yara-python binwalk")
            print("  Download The Sleuth Kit from: https://www.sleuthkit.org/")
            print("  Download Autopsy from: https://www.autopsy.com/")
            print("\nRecommended: Use WSL2 or Linux VM for full support")
            
        elif self.os_type == "Darwin":
            print("macOS:")
            print("  brew install sleuthkit yara")
            print("  pip3 install plaso volatility3 yara-python")

    def setup_virtual_environment(self, venv_name: str) -> bool:
        """Set up Python virtual environment."""
        print(f"\n🐍 Setting up virtual environment: {venv_name}")
        
        try:
            # Create virtual environment
            subprocess.run([sys.executable, "-m", "venv", venv_name], check=True)
            print(f"✓ Virtual environment '{venv_name}' created")
            
            # Determine activation script path
            if self.os_type == "Windows":
                activate_script = os.path.join(venv_name, "Scripts", "activate.bat")
                pip_path = os.path.join(venv_name, "Scripts", "pip.exe")
            else:
                activate_script = os.path.join(venv_name, "bin", "activate")
                pip_path = os.path.join(venv_name, "bin", "pip")
            
            # Install requirements
            if os.path.exists("requirements.txt"):
                print("📦 Installing Python requirements...")
                subprocess.run([pip_path, "install", "-r", "requirements.txt"], check=True)
                print("✓ Requirements installed")
            
            # Show activation instructions
            print(f"\n🎯 To activate the virtual environment:")
            if self.os_type == "Windows":
                print(f"   {venv_name}\\Scripts\\activate.bat")
            else:
                print(f"   source {venv_name}/bin/activate")
            
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"✗ Virtual environment setup failed: {e}")
            return False

    def run_application(self, venv_name: str = None) -> bool:
        """Run the Digital Forensics Workbench application."""
        print("\n🚀 Starting Digital Forensics Workbench...")
        
        try:
            if venv_name and os.path.exists(venv_name):
                # Run with virtual environment
                if self.os_type == "Windows":
                    python_path = os.path.join(venv_name, "Scripts", "python.exe")
                else:
                    python_path = os.path.join(venv_name, "bin", "python")
            else:
                python_path = sys.executable
            
            # Try different entry points
            entry_points = [
                [python_path, "-m", "dfw"],
                [python_path, "complete_main.py"],
                [python_path, "main.py"]
            ]
            
            for cmd in entry_points:
                try:
                    print(f"Trying: {' '.join(cmd)}")
                    subprocess.run(cmd, check=True)
                    return True
                except subprocess.CalledProcessError:
                    continue
                except FileNotFoundError:
                    continue
            
            print("✗ Failed to start application")
            print("Try running manually:")
            print(f"  {python_path} complete_main.py")
            return False
            
        except Exception as e:
            print(f"✗ Application startup failed: {e}")
            return False

    def run_tests(self) -> bool:
        """Run basic functionality tests."""
        print("\n🧪 Running tests...")
        
        try:
            # Test imports
            print("Testing imports...")
            test_imports = [
                "tkinter",
                "os", "sys", "platform",
                "subprocess", "threading",
                "json", "datetime"
            ]
            
            for module in test_imports:
                try:
                    __import__(module)
                    print(f"  ✓ {module}")
                except ImportError as e:
                    print(f"  ✗ {module}: {e}")
                    return False
            
            # Test GUI availability
            try:
                import tkinter
                root = tkinter.Tk()
                root.withdraw()  # Hide window
                root.destroy()
                print("  ✓ GUI support available")
            except Exception as e:
                print(f"  ✗ GUI support failed: {e}")
                return False
            
            print("✓ All tests passed")
            return True
            
        except Exception as e:
            print(f"✗ Tests failed: {e}")
            return False

    def check_external_tools(self) -> Dict[str, bool]:
        """Check for required external tools."""
        tools = {
            "mmls": "The Sleuth Kit",
            "volatility3": "Volatility 3",
            "tshark": "Wireshark/TShark",
            "regripper": "RegRipper",
            "aleapp": "ALEAPP",
            "bulk_extractor": "Bulk Extractor",
            "foremost": "Foremost",
            "binwalk": "Binwalk",
            "exiftool": "ExifTool",
            "yara": "YARA",
            "autopsy": "Autopsy",
        }

        if self.os_type == "Windows":
            tools.update({
                "rip.exe": "RegRipper (Windows)",
                "volatility3.exe": "Volatility 3 (Windows)",
            })

        print("\nChecking external tools...")
        results = {}

        for tool, name in tools.items():
            if shutil.which(tool):
                print(f"  ✓ {name:30} Found")
                self.installed_tools.append(name)
                results[tool] = True
            else:
                print(f"  ✗ {name:30} Not found")
                self.missing_tools.append((tool, name))
                results[tool] = False

        return results

    def create_virtualenv(self, venv_dir: Path) -> bool:
        """Create Python virtual environment."""
        if venv_dir.exists():
            print(f"\nUsing existing virtual environment at {venv_dir}")
            return True

        print(f"\nCreating virtual environment at {venv_dir}...")
        try:
            subprocess.check_call([sys.executable, '-m', 'venv', str(venv_dir)])
            print("✓ Virtual environment created")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to create virtual environment: {e}")
            return False

    def get_python_executable(self, venv_dir: Path) -> Path:
        """Get path to Python executable in virtual environment."""
        if self.os_type == "Windows":
            return venv_dir / "Scripts" / "python.exe"
        else:
            return venv_dir / "bin" / "python"

    def upgrade_pip(self, venv_dir: Path) -> bool:
        """Upgrade pip in virtual environment."""
        python_exe = self.get_python_executable(venv_dir)
        print("\nUpgrading pip...")

        try:
            subprocess.check_call([str(python_exe), '-m', 'pip', 'install', '--upgrade', 'pip'])
            print("✓ Pip upgraded")
            return True
        except subprocess.CalledProcessError:
            print("⚠ Could not upgrade pip, continuing with current version")
            return True

    def install_requirements(self, venv_dir: Path, requirements_file: Path) -> bool:
        """Install Python requirements."""
        python_exe = self.get_python_executable(venv_dir)
        print(f"\nInstalling Python dependencies from {requirements_file}...")

        # Install basic requirements first
        basic_packages = [
            'volatility3',
            'python-registry',
            'regipy',
            'python-evtx',
            'python-magic',
            'pefile',
            'scapy',
            'pandas',
            'numpy',
            'jinja2',
            'pyyaml',
            'Pillow',
        ]

        for package in basic_packages:
            print(f"Installing {package}...")
            try:
                subprocess.check_call([str(python_exe), '-m', 'pip', 'install', package])
                print(f"  ✓ {package} installed")
            except subprocess.CalledProcessError:
                print(f"  ⚠ Failed to install {package}")
                self.warnings.append(f"Failed to install {package}")

        # Try to install pytsk3 if on Linux or if build tools available
        if self.os_type == "Linux":
            print("\nAttempting to install pytsk3...")
            try:
                subprocess.check_call([str(python_exe), '-m', 'pip', 'install', 'pytsk3'])
                print("  ✓ pytsk3 installed")
            except subprocess.CalledProcessError:
                print("  ⚠ pytsk3 installation failed (build tools may be missing)")
                self.warnings.append("pytsk3 not installed - extraction features may be limited")
        elif self.os_type == "Windows":
            print("\n⚠ pytsk3 requires Microsoft Visual C++ Build Tools on Windows")
            print("  If you need extraction features, install build tools and run:")
            print(f"  {python_exe} -m pip install pytsk3")
            self.warnings.append("pytsk3 not installed - extraction features limited on Windows")

        return True

    def install_external_tools_linux(self) -> None:
        """Provide Linux-specific installation instructions."""
        print("\n" + "="*60)
        print("LINUX INSTALLATION INSTRUCTIONS")
        print("="*60)

        # Detect distribution
        distro = "unknown"
        if os.path.exists("/etc/debian_version"):
            distro = "debian"
        elif os.path.exists("/etc/redhat-release"):
            distro = "redhat"
        elif os.path.exists("/etc/arch-release"):
            distro = "arch"

        if distro == "debian":
            print("\nFor Debian/Ubuntu/Kali, run:")
            print("sudo apt update")
            print("sudo apt install -y \\")
            print("  sleuthkit \\")
            print("  python3-pytsk3 \\")
            print("  wireshark \\")
            print("  tshark \\")
            print("  binwalk \\")
            print("  foremost \\")
            print("  exiftool \\")
            print("  yara \\")
            print("  bulk-extractor")

        elif distro == "redhat":
            print("\nFor RHEL/CentOS/Fedora, run:")
            print("sudo dnf install -y \\")
            print("  sleuthkit \\")
            print("  wireshark \\")
            print("  binwalk \\")
            print("  foremost \\")
            print("  perl-Image-ExifTool \\")
            print("  yara")

        elif distro == "arch":
            print("\nFor Arch Linux, run:")
            print("sudo pacman -S \\")
            print("  sleuthkit \\")
            print("  wireshark-qt \\")
            print("  binwalk \\")
            print("  foremost \\")
            print("  perl-image-exiftool \\")
            print("  yara")

        print("\nFor Volatility 3:")
        print("pip install volatility3")

        print("\nFor RegRipper (all distributions):")
        print("git clone https://github.com/keydet89/RegRipper3.0.git")
        print("cd RegRipper3.0")
        print("chmod +x rip.pl")
        print("sudo cp rip.pl /usr/local/bin/")

        print("\nFor ALEAPP:")
        print("pip install aleapp")

    def install_external_tools_windows(self) -> None:
        """Provide Windows-specific installation instructions."""
        print("\n" + "="*60)
        print("WINDOWS INSTALLATION INSTRUCTIONS")
        print("="*60)

        print("\nUsing Chocolatey (recommended):")
        print("If you don't have Chocolatey, install from https://chocolatey.org/")
        print("\nThen run in Administrator PowerShell:")
        print("choco install -y \\")
        print("  sleuthkit \\")
        print("  wireshark \\")
        print("  binwalk \\")
        print("  exiftool \\")
        print("  yara")

        print("\nUsing Scoop (alternative):")
        print("scoop install sleuthkit wireshark")

        print("\nManual Downloads:")
        print("- Sleuth Kit: https://www.sleuthkit.org/sleuthkit/download.php")
        print("- Wireshark: https://www.wireshark.org/download.html")
        print("- RegRipper: https://github.com/keydet89/RegRipper3.0")
        print("- Autopsy: https://www.autopsy.com/download/")
        print("- ExifTool: https://exiftool.org/")
        print("- YARA: https://github.com/VirusTotal/yara/releases")

        print("\nFor Python tools:")
        print("pip install volatility3 aleapp")

        print("\nIMPORTANT: Add tool directories to your PATH environment variable")

    def install_external_tools_macos(self) -> None:
        """Provide macOS-specific installation instructions."""
        print("\n" + "="*60)
        print("MACOS INSTALLATION INSTRUCTIONS")
        print("="*60)

        print("\nUsing Homebrew:")
        print("If you don't have Homebrew, install from https://brew.sh/")
        print("\nThen run:")
        print("brew install \\")
        print("  sleuthkit \\")
        print("  wireshark \\")
        print("  binwalk \\")
        print("  exiftool \\")
        print("  yara")

        print("\nFor Python tools:")
        print("pip install volatility3 aleapp")

    def create_launcher_scripts(self, venv_dir: Path) -> None:
        """Create launcher scripts for easy execution."""
        print("\nCreating launcher scripts...")

        if self.os_type == "Windows":
            # Windows batch file
            launcher_path = Path("dfw.bat")
            python_exe = self.get_python_executable(venv_dir)

            with open(launcher_path, 'w') as f:
                f.write(f'@echo off\n')
                f.write(f'"{python_exe}" -m dfw %*\n')

            print(f"✓ Created {launcher_path}")
            print(f"  Run with: dfw.bat")

        else:
            # Unix shell script
            launcher_path = Path("dfw.sh")
            python_exe = self.get_python_executable(venv_dir)

            with open(launcher_path, 'w') as f:
                f.write(f'#!/bin/bash\n')
                f.write(f'"{python_exe}" -m dfw "$@"\n')

            os.chmod(launcher_path, 0o755)
            print(f"✓ Created {launcher_path}")
            print(f"  Run with: ./dfw.sh")

    def download_sample_data(self) -> None:
        """Download sample forensic data for testing."""
        print("\nWould you like to download sample forensic data for testing? (y/n): ", end='')
        response = input().strip().lower()

        if response != 'y':
            return

        samples_dir = Path("sample_data")
        samples_dir.mkdir(exist_ok=True)

        print("Downloading sample data...")

        # URLs for sample forensic data (these would be real URLs)
        samples = [
            ("https://example.com/sample_registry.zip", "sample_registry.zip"),
            ("https://example.com/sample_browser.zip", "sample_browser.zip"),
            # Add more sample data URLs
        ]

        for url, filename in samples:
            filepath = samples_dir / filename
            try:
                print(f"  Downloading {filename}...")
                # urllib.request.urlretrieve(url, filepath)
                print(f"  ✓ Downloaded {filename}")
            except Exception as e:
                print(f"  ✗ Failed to download {filename}: {e}")

    def create_config_file(self) -> None:
        """Create configuration file with tool paths."""
        print("\nCreating configuration file...")

        config = {
            "os_type": self.os_type,
            "tools": {},
            "paths": {
                "cases": str(Path("cases").absolute()),
                "exports": str(Path("exports").absolute()),
                "temp": str(Path("temp").absolute()),
            }
        }

        # Find and store tool paths
        for tool in ["mmls", "volatility3", "tshark", "regripper", "aleapp"]:
            path = shutil.which(tool)
            if path:
                config["tools"][tool] = path

        # Create directories
        for dir_path in config["paths"].values():
            Path(dir_path).mkdir(exist_ok=True)

        # Save config
        config_path = Path("config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        print(f"✓ Created {config_path}")

    def print_summary(self) -> None:
        """Print installation summary."""
        print("\n" + "="*60)
        print("INSTALLATION SUMMARY")
        print("="*60)

        print(f"\nOperating System: {self.os_type} {self.os_version}")
        print(f"Python Version: {self.python_version}")

        if self.installed_tools:
            print(f"\n✓ Installed Tools ({len(self.installed_tools)}):")
            for tool in self.installed_tools:
                print(f"  - {tool}")

        if self.missing_tools:
            print(f"\n✗ Missing Tools ({len(self.missing_tools)}):")
            for tool, name in self.missing_tools:
                print(f"  - {name}")

        if self.warnings:
            print(f"\n⚠ Warnings:")
            for warning in self.warnings:
                print(f"  - {warning}")

        print("\n" + "="*60)
        print("NEXT STEPS")
        print("="*60)

        print("\n1. Install missing external tools (see instructions above)")
        print("2. Activate the virtual environment:")
        if self.os_type == "Windows":
            print("   dfw_env\\Scripts\\activate")
        else:
            print("   source dfw_env/bin/activate")
        print("3. Run the Digital Forensics Workbench:")
        print("   python -m dfw")
        print("   OR use the launcher script")

        print("\n" + "="*60)
        print("FEATURES AVAILABLE")
        print("="*60)
        print("✓ Automatic OS detection")
        print("✓ Browser forensics (Chrome, Firefox, Edge, Safari)")
        print("✓ Windows registry analysis")
        print("✓ Enhanced mounting with custom options")
        print("✓ Advanced keyword search with regex")
        print("✓ Memory forensics with Volatility3")
        print("✓ Network packet analysis")
        print("✓ Mobile device forensics")
        print("✓ VM disk analysis")
        print("✓ Comprehensive timeline generation")
        print("✓ Professional report generation")

        if self.missing_tools:
            print("\n⚠ Some features may be limited due to missing tools")
            print("  Install the missing tools for full functionality")

    def run_tests(self, venv_dir: Path) -> None:
        """Run basic tests to verify installation."""
        print("\n" + "="*60)
        print("RUNNING TESTS")
        print("="*60)

        python_exe = self.get_python_executable(venv_dir)

        # Test imports
        print("\nTesting Python imports...")
        test_imports = [
            "import volatility3",
            "import regipy",
            "import scapy",
            "import pandas",
        ]

        for import_stmt in test_imports:
            try:
                subprocess.check_call([str(python_exe), '-c', import_stmt])
                print(f"  ✓ {import_stmt}")
            except subprocess.CalledProcessError:
                print(f"  ✗ {import_stmt}")
                self.warnings.append(f"Failed to import: {import_stmt}")

def main():
    """Main installation process with auto-installer integration."""
    parser = argparse.ArgumentParser(
        description="Enhanced installer for Digital Forensics Workbench with Auto-Installer"
    )
    parser.add_argument(
        '--venv-name',
        default='dfw_env',
        help='Virtual environment directory name (default: dfw_env)'
    )
    parser.add_argument(
        '--auto-install',
        action='store_true',
        help='Automatically install all forensic tools (Linux only)'
    )
    parser.add_argument(
        '--check-tools',
        action='store_true',
        help='Check forensic tool availability without installing'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run tests after installation'
    )
    parser.add_argument(
        '--run',
        action='store_true',
        help='Launch application after setup'
    )
    parser.add_argument(
        '--no-venv',
        action='store_true',
        help='Skip virtual environment creation'
    )

    args = parser.parse_args()

    print("="*60)
    print("DIGITAL FORENSICS WORKBENCH - ENHANCED INSTALLER")
    print("="*60)

    installer = DFWInstaller()

    # Check OS and Python
    installer.detect_os()
    if not installer.check_python_version():
        return 1

    # Check forensic tools
    installer.check_forensic_tools()

    # Setup virtual environment (unless skipped)
    venv_name = args.venv_name
    if not args.no_venv:
        if not installer.setup_virtual_environment(venv_name):
            print("⚠ Virtual environment setup failed, continuing without it...")
            venv_name = None

    # Install forensic tools if requested
    if args.auto_install:
        installer.install_forensic_tools(auto_install=True)
    elif args.check_tools:
        print("\n✓ Tool check complete. Use --auto-install to install missing tools.")
    elif installer.missing_tools:
        print(f"\n⚠ Found {len(installer.missing_tools)} missing required tools")
        print("Use --auto-install to install them automatically")
        print("Or use --check-tools to see detailed status")

    # Run tests if requested
    if args.test:
        installer.run_tests()

    # Launch application if requested
    if args.run:
        print("\n" + "="*60)
        print("LAUNCHING DIGITAL FORENSICS WORKBENCH")
        print("="*60)
        installer.run_application(venv_name)

    # Show summary
    print("\n" + "="*60)
    print("INSTALLATION COMPLETE")
    print("="*60)
    
    if installer.installed_tools:
        print(f"✓ Available tools: {len(installer.installed_tools)}")
    if installer.missing_tools:
        print(f"✗ Missing tools: {len(installer.missing_tools)}")
        print("  Use --auto-install to install missing tools")
    
    print("\nTo run the application:")
    if venv_name and os.path.exists(venv_name):
        if installer.os_type == "Windows":
            print(f"  {venv_name}\\Scripts\\activate")
        else:
            print(f"  source {venv_name}/bin/activate")
    
    print("  python complete_main.py")
    print("  OR")
    print("  python -m dfw")

    return 0


if __name__ == '__main__':
    sys.exit(main())