# Digital Forensics Workbench - Enhanced Case Management Edition

A comprehensive digital forensics toolkit with advanced case management, persistent mounted drives, and robust error handling.

## 🆕 What's New in Version 2.0

### Case Management System
- **Persistent Cases**: Create and save forensic cases with all associated data
- **Mounted Drive Memory**: Application remembers mounted drives between sessions
- **Automatic Detection**: Detects existing mounted drives on startup
- **Case History**: Browse and reopen previous investigations
- **Evidence Tracking**: Complete tracking of all evidence items with metadata

### Enhanced User Experience
- **Intuitive Case Management**: Easy case creation and loading workflows
- **Visual Mount Status**: See all mounted drives and their status at a glance
- **Robust Error Handling**: Comprehensive error handling with helpful suggestions
- **Professional Logging**: Complete audit trail of all operations

## 🚀 Quick Start

### First Time Setup
1. **Launch Application**: Run the main application
2. **Case Selection**: Choose to create a new case or load existing
3. **Mount Evidence**: Mount your disk images (saved automatically)
4. **Start Investigation**: Use all forensic tools as normal
5. **Resume Anytime**: Reopen your case to continue where you left off

### Creating a New Case
```
File → New Case
- Enter case name, number, and investigator details
- Add description for the investigation
- Case directory is created automatically
```

### Loading Existing Case
```
File → Open Case
- Browse available cases or select directory
- All mounted drives and evidence are restored
- Continue investigation seamlessly
```

## 📋 Core Features

### Case Management
- **Case Information**: Store investigator details, case numbers, descriptions
- **Evidence Tracking**: Automatic tracking of all evidence items with hashes
- **Mounted Drive Persistence**: Remember all mounted drives between sessions
- **Case Validation**: Integrity checking for cases and evidence
- **Export Capabilities**: Export case information for reporting

### Forensic Analysis Tools
- **OS Detection**: Automatic operating system detection and analysis
- **File System Analysis**: Browse and analyze mounted file systems
- **Browser Forensics**: Extract and analyze browser artifacts
- **Registry Analysis**: Windows registry examination tools
- **Timeline Analysis**: Create and analyze forensic timelines
- **Memory Analysis**: Memory dump examination capabilities
- **Network Forensics**: Network traffic and log analysis
- **Mobile Forensics**: Mobile device analysis tools

### Advanced Mounting
- **Multiple Format Support**: Support for various disk image formats
- **Offset Mounting**: Hex and decimal offset support for complex images
- **File System Detection**: Automatic detection of NTFS, EXT, FAT, HFS+
- **Read-Only Safety**: Safe read-only mounting by default
- **Hash Verification**: Automatic SHA256 hash calculation for integrity

### Error Handling & Logging
- **Comprehensive Error Handling**: Graceful handling of all error conditions
- **Detailed Logging**: Complete audit trail in ~/DFW_Logs/
- **User-Friendly Messages**: Clear error messages with helpful suggestions
- **Recovery Mechanisms**: Automatic recovery from common issues

## 🛠️ Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-tk python3-pip

# Install Python dependencies
pip3 install -r requirements.txt
```

### Running the Application
```bash
# Method 1: Direct execution
python3 complete_main.py

# Method 2: Module execution
python3 -m dfw_project

# Method 3: Using the installer
python3 install_dfw.py
```

## 📁 Project Structure

```
dfw_project/
├── complete_main.py         # Main application with case management
├── case_manager.py          # Case management functionality
├── error_handler.py         # Centralized error handling
├── gui.py                   # GUI components
├── forensic_tools.py        # Forensic analysis tools
├── mount.py                 # Disk mounting utilities
├── os_detector.py           # Operating system detection
├── browser_forensics.py     # Browser artifact analysis
├── registry_analyzer.py     # Windows registry analysis
├── tool_manager.py          # External tool management
├── notes_terminal.py        # Case notes and terminal
├── auto_installer.py        # Automatic tool installation
├── requirements*.txt        # Python dependencies
└── README_UPDATED.md        # This file
```

## 🔧 Configuration

### Case Storage
- **Default Location**: `~/DFW_Cases/`
- **Case Structure**: Each case gets its own directory with subdirectories for evidence, exports, notes, and reports
- **Case Files**: JSON format for easy backup and sharing

### Logging
- **Log Location**: `~/DFW_Logs/`
- **Log Format**: Timestamped entries with severity levels
- **Log Rotation**: Daily log files for easy management

### Mount Points
- **Default Location**: `/mnt/` directory
- **Auto-Detection**: Scans for existing mounts on startup
- **Validation**: Checks mount status and accessibility

## 💡 Usage Examples

### Basic Workflow
```python
# 1. Start application and create/load case
# 2. Mount disk image
File → Mount/Extract → Select image → Force Mount

# 3. The mount is automatically saved to your case
# 4. Conduct analysis using any forensic tool
# 5. Save case progress
File → Save Case

# 6. Later: reopen case and all mounts are remembered
File → Open Case → Select your case
```

### Advanced Case Management
```python
# Create detailed case
case_info = {
    'case_name': 'Corporate Data Breach Investigation',
    'case_number': 'INV-2024-001',
    'investigator': 'John Smith',
    'description': 'Investigation of suspected data exfiltration'
}

# Evidence is automatically tracked
evidence_items = [
    'laptop_image.dd',
    'server_logs.zip',
    'network_capture.pcap'
]

# Mounted drives persist between sessions
mounted_drives = [
    '/mnt/laptop_c_drive',
    '/mnt/laptop_d_drive',
    '/mnt/server_disk'
]
```

## 🔍 Forensic Capabilities

### File System Analysis
- **File Browser**: Navigate mounted file systems
- **Metadata Extraction**: File timestamps, permissions, ownership
- **Deleted File Recovery**: Identify and recover deleted files
- **Hash Calculation**: MD5, SHA1, SHA256 for evidence integrity

### Operating System Artifacts
- **Windows**: Registry, event logs, prefetch, recent files
- **Linux**: System logs, bash history, cron jobs, user accounts
- **macOS**: System logs, plist files, user artifacts

### Network Forensics
- **Log Analysis**: Web server, firewall, and system logs
- **Traffic Analysis**: Network packet capture examination
- **Connection Tracking**: Network connection histories

### Browser Forensics
- **History Extraction**: Browsing history from all major browsers
- **Cookie Analysis**: Session and tracking cookie examination
- **Download History**: File download tracking and analysis
- **Cache Analysis**: Browser cache content examination

## 🛡️ Security Features

### Evidence Integrity
- **Hash Verification**: Automatic hash calculation and verification
- **Read-Only Mounting**: Safe examination without modification
- **Chain of Custody**: Complete tracking of evidence handling
- **Audit Logging**: Full audit trail of all operations

### Data Protection
- **Secure Storage**: Case files stored with appropriate permissions
- **Backup Safety**: Robust case file format prevents corruption
- **Error Recovery**: Graceful handling of hardware failures
- **Validation Checks**: Continuous integrity monitoring

## 🚨 Troubleshooting

### Common Issues

#### Mount Failures
```bash
# Permission issues
sudo chmod +x complete_main.py
sudo python3 complete_main.py

# Missing mount point
sudo mkdir -p /mnt/evidence
sudo chown $USER:$USER /mnt/evidence
```

#### Case Loading Issues
```bash
# Check case directory permissions
ls -la ~/DFW_Cases/

# Verify case file integrity
python3 -c "import json; print(json.load(open('case.json')))"
```

#### Missing Dependencies
```bash
# Install missing packages
pip3 install -r requirements.txt

# For GUI issues
sudo apt-get install python3-tk
```

### Error Logs
Check `~/DFW_Logs/` for detailed error information:
```bash
tail -f ~/DFW_Logs/dfw_$(date +%Y%m%d).log
```

## 🤝 Contributing

### Development Setup
```bash
git clone <repository>
cd dfw_project
pip3 install -r requirements.txt
python3 -m pytest tests/  # Run tests
```

### Code Style
- Follow PEP 8 guidelines
- Use type hints for all functions
- Add comprehensive docstrings
- Include error handling for all operations

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Original Digital Forensics Workbench contributors
- Open source forensic tools community
- Digital forensics research community

## 📞 Support

For issues, questions, or feature requests:
1. Check the error logs in `~/DFW_Logs/`
2. Review this documentation
3. Check the CHANGELOG.md for recent updates
4. Create an issue with detailed error information

---

**Note**: This enhanced version maintains full backward compatibility while adding powerful new case management features. All original functionality remains available and unchanged.

