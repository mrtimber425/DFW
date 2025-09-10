"""Case management module for Digital Forensics Workbench.

This module handles case files, evidence tracking, and mounted drive persistence.
"""

import os
import json
import datetime
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class MountedDrive:
    """Represents a mounted drive in a case."""
    image_path: str
    mount_point: str
    partition_index: Optional[int] = None
    offset: Optional[int] = None
    readonly: bool = True
    mount_time: Optional[str] = None
    image_hash: Optional[str] = None
    file_system: Optional[str] = None
    size_bytes: Optional[int] = None
    
    def __post_init__(self):
        if self.mount_time is None:
            self.mount_time = datetime.datetime.now().isoformat()


@dataclass
class EvidenceItem:
    """Represents an evidence item in a case."""
    name: str
    path: str
    item_type: str  # 'disk_image', 'memory_dump', 'file', 'directory'
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    added_time: Optional[str] = None
    description: Optional[str] = None
    
    def __post_init__(self):
        if self.added_time is None:
            self.added_time = datetime.datetime.now().isoformat()


@dataclass
class CaseInfo:
    """Case information structure."""
    case_name: str
    case_number: str
    investigator: str
    date_created: str
    description: str = ""
    case_id: Optional[str] = None
    
    def __post_init__(self):
        if self.case_id is None:
            # Generate unique case ID
            data = f"{self.case_name}{self.case_number}{self.date_created}"
            self.case_id = hashlib.md5(data.encode()).hexdigest()[:8]


class CaseManager:
    """Manages forensic cases, evidence, and mounted drives."""
    
    CASE_FILE_VERSION = "1.0"
    
    def __init__(self, case_directory: str = None):
        """Initialize case manager.
        
        Args:
            case_directory: Base directory for storing cases
        """
        if case_directory is None:
            case_directory = os.path.expanduser("~/DFW_Cases")
        
        self.case_directory = Path(case_directory)
        self.case_directory.mkdir(parents=True, exist_ok=True)
        
        self.current_case_path: Optional[Path] = None
        self.case_info: Optional[CaseInfo] = None
        self.evidence_items: List[EvidenceItem] = []
        self.mounted_drives: List[MountedDrive] = []
        
    def create_new_case(self, case_info: CaseInfo) -> str:
        """Create a new forensic case.
        
        Args:
            case_info: Case information
            
        Returns:
            Path to the created case directory
            
        Raises:
            ValueError: If case already exists
            OSError: If case directory cannot be created
        """
        # Create case directory name
        safe_name = "".join(c for c in case_info.case_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        case_dir_name = f"{safe_name}_{case_info.case_id}"
        case_path = self.case_directory / case_dir_name
        
        if case_path.exists():
            raise ValueError(f"Case directory already exists: {case_path}")
        
        try:
            # Create case directory structure
            case_path.mkdir(parents=True)
            (case_path / "evidence").mkdir()
            (case_path / "exports").mkdir()
            (case_path / "notes").mkdir()
            (case_path / "reports").mkdir()
            (case_path / "temp").mkdir()
            
            # Initialize case
            self.current_case_path = case_path
            self.case_info = case_info
            self.evidence_items = []
            self.mounted_drives = []
            
            # Save case file
            self.save_case()
            
            return str(case_path)
            
        except OSError as e:
            raise OSError(f"Failed to create case directory: {e}")
    
    def load_case(self, case_path: str) -> bool:
        """Load an existing case.
        
        Args:
            case_path: Path to case directory or case file
            
        Returns:
            True if case loaded successfully, False otherwise
        """
        case_path = Path(case_path)
        
        # If it's a directory, look for case.json
        if case_path.is_dir():
            case_file = case_path / "case.json"
        else:
            case_file = case_path
            case_path = case_file.parent
        
        if not case_file.exists():
            return False
        
        try:
            with open(case_file, 'r') as f:
                case_data = json.load(f)
            
            # Validate case file version
            if case_data.get('version') != self.CASE_FILE_VERSION:
                print(f"Warning: Case file version mismatch. Expected {self.CASE_FILE_VERSION}, got {case_data.get('version')}")
            
            # Load case info
            self.case_info = CaseInfo(**case_data['case_info'])
            
            # Load evidence items
            self.evidence_items = [EvidenceItem(**item) for item in case_data.get('evidence_items', [])]
            
            # Load mounted drives
            self.mounted_drives = [MountedDrive(**drive) for drive in case_data.get('mounted_drives', [])]
            
            self.current_case_path = case_path
            
            return True
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Error loading case file: {e}")
            return False
    
    def save_case(self) -> bool:
        """Save current case to file.
        
        Returns:
            True if saved successfully, False otherwise
        """
        if not self.current_case_path or not self.case_info:
            return False
        
        case_file = self.current_case_path / "case.json"
        
        try:
            case_data = {
                'version': self.CASE_FILE_VERSION,
                'case_info': asdict(self.case_info),
                'evidence_items': [asdict(item) for item in self.evidence_items],
                'mounted_drives': [asdict(drive) for drive in self.mounted_drives],
                'last_modified': datetime.datetime.now().isoformat()
            }
            
            with open(case_file, 'w') as f:
                json.dump(case_data, f, indent=2)
            
            return True
            
        except (OSError, json.JSONEncodeError) as e:
            print(f"Error saving case file: {e}")
            return False
    
    def add_evidence_item(self, evidence: EvidenceItem) -> bool:
        """Add evidence item to case.
        
        Args:
            evidence: Evidence item to add
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Check if evidence already exists
            for existing in self.evidence_items:
                if existing.path == evidence.path:
                    return False
            
            self.evidence_items.append(evidence)
            self.save_case()
            return True
            
        except Exception as e:
            print(f"Error adding evidence item: {e}")
            return False
    
    def remove_evidence_item(self, evidence_path: str) -> bool:
        """Remove evidence item from case.
        
        Args:
            evidence_path: Path of evidence item to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            self.evidence_items = [item for item in self.evidence_items if item.path != evidence_path]
            self.save_case()
            return True
            
        except Exception as e:
            print(f"Error removing evidence item: {e}")
            return False
    
    def add_mounted_drive(self, mounted_drive: MountedDrive) -> bool:
        """Add mounted drive to case.
        
        Args:
            mounted_drive: Mounted drive information
            
        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Remove existing mount for same image/mount point
            self.mounted_drives = [
                drive for drive in self.mounted_drives 
                if drive.image_path != mounted_drive.image_path or drive.mount_point != mounted_drive.mount_point
            ]
            
            self.mounted_drives.append(mounted_drive)
            self.save_case()
            return True
            
        except Exception as e:
            print(f"Error adding mounted drive: {e}")
            return False
    
    def remove_mounted_drive(self, mount_point: str) -> bool:
        """Remove mounted drive from case.
        
        Args:
            mount_point: Mount point of drive to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            self.mounted_drives = [drive for drive in self.mounted_drives if drive.mount_point != mount_point]
            self.save_case()
            return True
            
        except Exception as e:
            print(f"Error removing mounted drive: {e}")
            return False
    
    def get_mounted_drives(self) -> List[MountedDrive]:
        """Get list of mounted drives for current case.
        
        Returns:
            List of mounted drives
        """
        return self.mounted_drives.copy()
    
    def get_evidence_items(self) -> List[EvidenceItem]:
        """Get list of evidence items for current case.
        
        Returns:
            List of evidence items
        """
        return self.evidence_items.copy()
    
    def is_drive_mounted(self, mount_point: str) -> bool:
        """Check if a drive is currently mounted at the specified point.
        
        Args:
            mount_point: Mount point to check
            
        Returns:
            True if drive is mounted, False otherwise
        """
        if not os.path.exists(mount_point):
            return False
        
        try:
            # Check if mount point is actually mounted
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
            
            return mount_point in mounts
            
        except Exception:
            # Fallback: check if directory is not empty
            try:
                return len(os.listdir(mount_point)) > 0
            except Exception:
                return False
    
    def validate_mounted_drives(self) -> List[MountedDrive]:
        """Validate all mounted drives and return list of valid ones.
        
        Returns:
            List of currently valid mounted drives
        """
        valid_drives = []
        
        for drive in self.mounted_drives:
            if self.is_drive_mounted(drive.mount_point):
                valid_drives.append(drive)
        
        return valid_drives
    
    def get_case_summary(self) -> Dict[str, Any]:
        """Get summary of current case.
        
        Returns:
            Dictionary containing case summary
        """
        if not self.case_info:
            return {}
        
        valid_mounts = self.validate_mounted_drives()
        
        return {
            'case_info': asdict(self.case_info),
            'evidence_count': len(self.evidence_items),
            'mounted_drives_count': len(valid_mounts),
            'case_path': str(self.current_case_path) if self.current_case_path else None,
            'valid_mounts': [asdict(drive) for drive in valid_mounts]
        }
    
    def list_cases(self) -> List[Dict[str, str]]:
        """List all available cases.
        
        Returns:
            List of case information dictionaries
        """
        cases = []
        
        try:
            for case_dir in self.case_directory.iterdir():
                if case_dir.is_dir():
                    case_file = case_dir / "case.json"
                    if case_file.exists():
                        try:
                            with open(case_file, 'r') as f:
                                case_data = json.load(f)
                            
                            case_info = case_data.get('case_info', {})
                            cases.append({
                                'name': case_info.get('case_name', 'Unknown'),
                                'number': case_info.get('case_number', ''),
                                'investigator': case_info.get('investigator', ''),
                                'date_created': case_info.get('date_created', ''),
                                'path': str(case_dir)
                            })
                            
                        except Exception as e:
                            print(f"Error reading case {case_dir}: {e}")
            
            return sorted(cases, key=lambda x: x['date_created'], reverse=True)
            
        except Exception as e:
            print(f"Error listing cases: {e}")
            return []
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
            
        Returns:
            Hex digest of hash, or None if error
        """
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None
    
    def export_case_info(self, export_path: str) -> bool:
        """Export case information to JSON file.
        
        Args:
            export_path: Path to export file
            
        Returns:
            True if exported successfully, False otherwise
        """
        try:
            case_summary = self.get_case_summary()
            
            with open(export_path, 'w') as f:
                json.dump(case_summary, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting case info: {e}")
            return False

