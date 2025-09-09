# Digital Forensics Workbench - Professional Edition

A comprehensive digital forensics analysis platform with GUI interface for investigating disk images, memory dumps, and digital evidence.

## 🔍 Features

- **Disk Image Analysis**: Mount and analyze disk images (.dd, .raw, .E01)
- **File System Browser**: Interactive file tree with hex viewer
- **Browser Forensics**: Extract history, downloads, and artifacts
- **Registry Analysis**: Windows registry examination
- **Timeline Generation**: Create super timelines with Plaso/TSK
- **Memory Analysis**: Volatility integration for memory dumps
- **Search Functionality**: Keyword search across mounted drives
- **Hash Calculation**: MD5, SHA1, SHA256 with progress tracking
- **Evidence Management**: Case organization and documentation
- **Report Generation**: Professional forensic reports

## 📋 System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 4GB (8GB+ recommended for large images)
- **Storage**: 2GB free space
- **OS**: Windows 10+, Ubuntu 18.04+, or macOS 10.15+

### Recommended for Full Functionality
- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: 16GB+ for memory analysis
- **Storage**: 50GB+ for evidence processing

## 🚀 Quick Start

### Option 1: Automated Installation (Recommended)
```bash
# Clone or download the application
cd dfw

# Run the enhanced installer
python install_dfw.py --auto-install --run
```

### Option 2: Manual Installation
Choose your platform-specific guide below.

## 🐧 Linux Installation (Full Features)

### Ubuntu/Debian
```bash
# 1. Update system packages
sudo apt-get update

# 2. Install system dependencies
sudo apt-get install -y python3 python3-pip python3-tk python3-dev
sudo apt-get install -y build-essential git

# 3. Install forensic tools
sudo apt-get install -y sleuthkit bulk-extractor foremost yara
sudo apt-get install -y autopsy sleuthkit-java

# 4. Install Python packages
pip3 install -r requirements_linux.txt

# 5. Run the application
python3 install_dfw.py --auto-install --run
```

### Fedora/RHEL/CentOS
```bash
# 1. Install system dependencies
sudo dnf install -y python3 python3-pip python3-tkinter python3-devel
sudo dnf install -y gcc gcc-c++ git

# 2. Install forensic tools
sudo dnf install -y sleuthkit bulk-extractor foremost yara

# 3. Install Python packages
pip3 install -r requirements_linux.txt

# 4. Run the application
python3 install_dfw.py --auto-install --run
```

## 🪟 Windows Installation

### Prerequisites
1. **Install Python 3.8+** from [python.org](https://python.org)
   - ✅ Check "Add Python to PATH"
   - ✅ Check "Install for all users"

2. **Install Git** from [git-scm.com](https://git-scm.com)

### Installation Steps
```powershell
# 1. Open PowerShell as Administrator

# 2. Navigate to application directory
cd C:\path\to\dfw

# 3. Install Python packages
pip install -r requirements_windows.txt

# 4. Run the application
python install_dfw.py --auto-install --run
```

### Windows Limitations
⚠️ **Limited Tool Support**: Some forensic tools don't work on Windows
- ✅ **Available**: Volatility, YARA, basic analysis
- ❌ **Limited**: Plaso, Bulk Extractor, TSK timeline
- 💡 **Recommendation**: Use WSL2 or Linux VM for full functionality

### WSL2 Setup (Recommended for Windows)
```powershell
# 1. Install WSL2
wsl --install -d Ubuntu

# 2. Open Ubuntu terminal
wsl

# 3. Follow Linux installation steps
sudo apt-get update
sudo apt-get install -y python3-pip python3-tk sleuthkit
pip3 install -r requirements_linux.txt

# 4. Run application
python3 install_dfw.py --auto-install --run
```

## 🍎 macOS Installation

```bash
# 1. Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python and dependencies
brew install python python-tk

# 3. Install available forensic tools
brew install sleuthkit yara

# 4. Install Python packages
pip3 install -r requirements_minimal.txt

# 5. Run the application
python3 install_dfw.py --auto-install --run
```

## 🔧 Manual Tool Installation

### Timeline Tools
```bash
# Plaso (Linux only)
pip3 install plaso

# The Sleuth Kit
# Ubuntu: sudo apt-get install sleuthkit
# Windows: Download from sleuthkit.org
# macOS: brew install sleuthkit
```

### Additional Tools
```bash
# YARA (malware detection)
# Ubuntu: sudo apt-get install yara
# Windows: pip install yara-python
# macOS: brew install yara

# Bulk Extractor (Linux only)
sudo apt-get install bulk-extractor

# Volatility 3 (all platforms)
pip3 install volatility3
```

## 📖 Usage Guide

### 1. Mount Disk Image
```
1. Click "Browse" to select disk image (.dd, .raw, .E01)
2. Set mount point (or click "Create Dir" for new directory)
3. Click "Force Mount" for direct mounting
4. File tree automatically loads in left sidebar
```

### 2. Browse Files
```
- Use file tree in left sidebar to navigate
- Double-click files to open in hex viewer
- Use refresh (↻), expand (▼), collapse (▶) controls
```

### 3. Search for Evidence
```
1. Go to "Search" tab
2. Directory auto-populated with mount point
3. Enter keywords: "password, login, admin"
4. Click "Search" for results with context
```

### 4. Browser Analysis
```
1. Go to "Browser" tab
2. Click "Analyze All Browsers"
3. View history and downloads in tabs
4. Export results for reports
```

### 5. Generate Timeline
```
1. Go to "Timeline" tab
2. Click "Generate with Plaso" (Linux)
3. Or "Generate with TSK" (all platforms)
4. Export timeline for analysis
```

## 🛠️ Troubleshooting

### Common Issues

#### "tkinter not found"
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora/RHEL
sudo dnf install python3-tkinter

# Windows: Reinstall Python with tkinter option
```

#### "Tool not available" errors
```bash
# Check tool installation
which mmls          # Should show /usr/bin/mmls
which volatility3   # Should show path
python3 -c "import yara; print('YARA OK')"

# Install missing tools
sudo apt-get install sleuthkit  # Linux
pip3 install volatility3       # All platforms
```

#### Mount permission errors
```bash
# Add user to disk group (Linux)
sudo usermod -a -G disk $USER
# Logout and login again

# Or run with sudo
sudo python3 install_dfw.py --auto-install --run
```

#### Slow file tree loading
- File tree loads progressively for performance
- Large directories limited to 100 items
- Use search function for specific files

### Performance Tips

1. **Use SSD storage** for evidence files
2. **Increase RAM** for large disk images
3. **Close unused tabs** to save memory
4. **Use search** instead of browsing large directories
5. **Mount read-only** to prevent evidence modification

## 📁 Project Structure

```
dfw/
├── dfw/                    # Main application package
│   ├── __init__.py
│   ├── complete_main.py    # Main application
│   ├── auto_installer.py   # Tool installer
│   ├── browser_forensics.py
│   ├── registry_analyzer.py
│   ├── tool_manager.py
│   └── ...
├── requirements.txt        # General requirements
├── requirements_linux.txt  # Linux-specific
├── requirements_windows.txt # Windows-specific
├── requirements_minimal.txt # Minimal installation
├── install_dfw.py         # Enhanced installer
└── README.md              # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Getting Help
- **Documentation**: Check this README first
- **Issues**: Create GitHub issue with error details
- **Discussions**: Use GitHub Discussions for questions

### Reporting Bugs
Include the following information:
- Operating system and version
- Python version: `python3 --version`
- Error message and full traceback
- Steps to reproduce the issue

### Feature Requests
- Describe the forensic use case
- Explain expected behavior
- Provide examples if possible

## 🔄 Updates

### Version History
- **v2.0**: Added file tree browser, enhanced search, auto-installer
- **v1.5**: Timeline generation, memory analysis integration
- **v1.0**: Initial release with basic forensic capabilities

### Staying Updated
```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Run with latest features
python3 install_dfw.py --auto-install --run
```

---

**Digital Forensics Workbench** - Professional forensic analysis made accessible.

For questions or support, please create an issue on GitHub.

