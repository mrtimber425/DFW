# Digital Forensics Workbench - Installation Guide

## 🎯 Choose Your Installation Method

### 🚀 Method 1: One-Click Installation (Recommended)
```bash
python install_dfw.py --auto-install --run
```

### 🔧 Method 2: Platform-Specific Installation
Choose your operating system below for detailed instructions.

---

## 🐧 Linux Installation (Full Features)

### Ubuntu 20.04+ / Debian 11+

#### Step 1: System Preparation
```bash
# Update package lists
sudo apt-get update && sudo apt-get upgrade -y

# Install Python and development tools
sudo apt-get install -y python3 python3-pip python3-tk python3-dev
sudo apt-get install -y build-essential git curl wget
```

#### Step 2: Install Forensic Tools
```bash
# Core forensic tools
sudo apt-get install -y sleuthkit sleuthkit-java autopsy
sudo apt-get install -y bulk-extractor foremost scalpel
sudo apt-get install -y yara exiftool binwalk

# Network analysis tools
sudo apt-get install -y wireshark-common tshark

# Additional utilities
sudo apt-get install -y hexedit ghex bless
```

#### Step 3: Install Python Packages
```bash
# Install from Linux requirements
pip3 install -r requirements_linux.txt

# Or install minimal set
pip3 install -r requirements_minimal.txt
```

#### Step 4: Install Timeline Tools (Optional)
```bash
# Plaso for super timeline generation
pip3 install plaso

# Alternative: Use Docker for Plaso
docker pull log2timeline/plaso
```

#### Step 5: Run Application
```bash
# With auto-installer
python3 install_dfw.py --auto-install --run

# Or direct execution
python3 -m dfw
```

### Fedora 35+ / RHEL 8+ / CentOS Stream

#### Step 1: System Preparation
```bash
# Update system
sudo dnf update -y

# Install Python and development tools
sudo dnf install -y python3 python3-pip python3-tkinter python3-devel
sudo dnf install -y gcc gcc-c++ git curl wget
```

#### Step 2: Install Forensic Tools
```bash
# Enable EPEL repository (RHEL/CentOS)
sudo dnf install -y epel-release

# Install available tools
sudo dnf install -y sleuthkit yara
sudo dnf install -y hexedit

# Build tools from source if needed
sudo dnf groupinstall -y "Development Tools"
```

#### Step 3: Install Python Packages
```bash
pip3 install -r requirements_linux.txt
```

### Arch Linux / Manjaro

#### Step 1: System Preparation
```bash
# Update system
sudo pacman -Syu

# Install Python and tools
sudo pacman -S python python-pip tk git base-devel
```

#### Step 2: Install Forensic Tools
```bash
# Install from official repos
sudo pacman -S sleuthkit yara binwalk

# Install from AUR (using yay)
yay -S bulk-extractor autopsy
```

#### Step 3: Install Python Packages
```bash
pip install -r requirements_linux.txt
```

---

## 🪟 Windows Installation

### Prerequisites

#### 1. Install Python 3.8+
1. Download from [python.org](https://www.python.org/downloads/)
2. **Important**: Check these boxes during installation:
   - ✅ "Add Python to PATH"
   - ✅ "Install for all users"
   - ✅ "Install pip"
   - ✅ "Install tkinter"

#### 2. Install Git (Optional)
- Download from [git-scm.com](https://git-scm.com/download/win)

#### 3. Install Visual C++ Build Tools (For some packages)
- Download "Microsoft C++ Build Tools" from Microsoft

### Installation Steps

#### Method A: PowerShell Installation
```powershell
# Open PowerShell as Administrator
# Navigate to application directory
cd C:\path\to\dfw

# Install Python packages
pip install -r requirements_windows.txt

# Run application
python install_dfw.py --auto-install --run
```

#### Method B: Command Prompt Installation
```cmd
# Open Command Prompt as Administrator
cd C:\path\to\dfw

# Install packages
pip install -r requirements_windows.txt

# Run application
python install_dfw.py --auto-install --run
```

### Windows-Specific Tools

#### Manual Tool Installation
1. **The Sleuth Kit**:
   - Download from [sleuthkit.org](https://www.sleuthkit.org/sleuthkit/download.php)
   - Install to `C:\Program Files\SleuthKit`
   - Add to PATH: `C:\Program Files\SleuthKit\bin`

2. **Volatility 3**:
   ```cmd
   pip install volatility3
   ```

3. **YARA**:
   ```cmd
   pip install yara-python
   ```

### Windows Limitations
- ❌ Plaso (timeline generation) - Use WSL2 or Docker
- ❌ Bulk Extractor - Requires compilation
- ❌ Some Linux-specific tools
- ✅ Basic analysis, Volatility, YARA work fine

---

## 🔄 WSL2 Installation (Recommended for Windows)

### Step 1: Enable WSL2
```powershell
# Run in PowerShell as Administrator
wsl --install -d Ubuntu

# Restart computer when prompted
```

### Step 2: Configure Ubuntu
```bash
# Open Ubuntu from Start Menu
# Update system
sudo apt update && sudo apt upgrade -y

# Follow Linux installation steps
sudo apt-get install -y python3-pip python3-tk sleuthkit
pip3 install -r requirements_linux.txt
```

### Step 3: Access Windows Files
```bash
# Windows C: drive is at /mnt/c/
cd /mnt/c/Users/YourName/Desktop/evidence

# Run application
python3 install_dfw.py --auto-install --run
```

---

## 🍎 macOS Installation

### Prerequisites

#### Install Homebrew
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Install Xcode Command Line Tools
```bash
xcode-select --install
```

### Installation Steps

#### Step 1: Install Python and Dependencies
```bash
# Install Python with tkinter
brew install python python-tk

# Install development tools
brew install git curl wget
```

#### Step 2: Install Available Forensic Tools
```bash
# Install what's available via Homebrew
brew install sleuthkit yara binwalk exiftool

# Install additional tools
brew install hexedit
```

#### Step 3: Install Python Packages
```bash
# Use minimal requirements for macOS
pip3 install -r requirements_minimal.txt

# Or try full Linux requirements (some may fail)
pip3 install -r requirements_linux.txt
```

#### Step 4: Run Application
```bash
python3 install_dfw.py --auto-install --run
```

### macOS Limitations
- Some forensic tools not available via Homebrew
- May need to compile tools from source
- Timeline generation limited

---

## 🐳 Docker Installation (All Platforms)

### Create Dockerfile
```dockerfile
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-tk \
    sleuthkit bulk-extractor foremost yara \
    git curl wget \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements_linux.txt

# Run application
CMD ["python3", "install_dfw.py", "--auto-install", "--run"]
```

### Build and Run
```bash
# Build image
docker build -t dfw .

# Run with X11 forwarding (Linux)
docker run -it --rm \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v $(pwd)/evidence:/evidence \
    dfw

# Run with VNC (Windows/macOS)
docker run -it --rm -p 5900:5900 dfw
```

---

## 🔍 Verification and Testing

### Test Installation
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Test GUI support
python3 -c "import tkinter; print('GUI OK')"

# Test forensic tools
which mmls          # Should show path
volatility3 --help  # Should show help
python3 -c "import yara; print('YARA OK')"

# Run application test
python3 install_dfw.py --check-tools
```

### Performance Test
```bash
# Create test case
mkdir test_evidence
dd if=/dev/zero of=test_evidence/test.dd bs=1M count=100

# Mount and test
python3 install_dfw.py --test --run
```

---

## 🛠️ Troubleshooting

### Common Installation Issues

#### Python/Pip Issues
```bash
# Ubuntu: Python not found
sudo apt-get install python3 python3-pip

# Windows: Python not in PATH
# Reinstall Python with "Add to PATH" checked

# macOS: Permission denied
sudo chown -R $(whoami) /usr/local/lib/python3.*/site-packages
```

#### GUI Issues
```bash
# Linux: tkinter not found
sudo apt-get install python3-tk

# WSL2: Display not working
export DISPLAY=:0
# Install VcXsrv on Windows

# macOS: GUI not showing
# Install XQuartz from xquartz.org
```

#### Tool Installation Issues
```bash
# Ubuntu: Package not found
sudo apt-get update
sudo add-apt-repository universe

# Fedora: EPEL not enabled
sudo dnf install epel-release

# Build from source if package unavailable
git clone https://github.com/tool/repo
cd repo && make && sudo make install
```

#### Permission Issues
```bash
# Linux: Mount permission denied
sudo usermod -a -G disk $USER
# Logout and login

# Windows: Access denied
# Run PowerShell as Administrator

# macOS: Permission denied
sudo chown -R $(whoami) /usr/local
```

### Getting Help

#### Check Logs
```bash
# Application logs
tail -f ~/.dfw/logs/application.log

# System logs
journalctl -f  # Linux
# Event Viewer  # Windows
```

#### Report Issues
Include this information:
- Operating system and version
- Python version: `python3 --version`
- Installation method used
- Complete error message
- Output of: `python3 install_dfw.py --check-tools`

---

## 📦 Package Management

### Update Installation
```bash
# Update application
git pull origin main

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Update system tools
sudo apt-get update && sudo apt-get upgrade  # Linux
brew upgrade  # macOS
```

### Clean Installation
```bash
# Remove Python packages
pip3 uninstall -r requirements.txt -y

# Remove application
rm -rf dfw/

# Fresh installation
git clone https://github.com/your-repo/dfw.git
cd dfw
python3 install_dfw.py --auto-install --run
```

---

**Installation complete!** 🎉

Run `python3 install_dfw.py --auto-install --run` to start the Digital Forensics Workbench.

