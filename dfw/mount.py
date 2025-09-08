"""Functions for examining and mounting disk images.

This module wraps common operations for working with raw disk images
such as those produced by dd. It uses The Sleuth Kit (mmls) to
enumerate partitions and calculates offsets into the image. For
read‑only mounting on Linux it invokes the system ``mount`` command
with appropriate options. On Windows, or when root privileges are not
available, a fallback extraction mechanism utilising the ``pytsk3``
library is provided; this reads the filesystem through Sleuth Kit's
Python bindings and copies files into a destination directory.

Note: Mounting disk images typically requires administrative
privileges on Linux. The caller should ensure that the process has
sufficient privileges or that the user has configured ``sudo`` to
allow mount operations without a password. When using the
extraction‑based approach no special privileges are necessary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

try:
    import pytsk3  # type: ignore
except ImportError:
    pytsk3 = None  # type: ignore


@dataclass
class Partition:
    """Represents a partition entry discovered via mmls.

    Attributes:
        index: The numeric index of the partition as reported by mmls.
        start_sector: The starting sector number (512‑byte units).
        end_sector: The ending sector number.
        length: The number of sectors in the partition.
        description: A descriptive string provided by mmls (e.g. NTFS, Linux).
        offset: The byte offset into the image where this partition begins.
    """
    index: int
    start_sector: int
    end_sector: int
    length: int
    description: str
    offset: int


def parse_partitions(image_path: str) -> List[Partition]:
    """Return a list of Partition objects discovered in a disk image.

    This function invokes ``mmls`` (part of The Sleuth Kit) on the
    provided image file and parses its output to extract partition
    information. Only lines matching the expected partition table
    output are considered. If ``mmls`` is unavailable or an error
    occurs, an empty list is returned.

    Args:
        image_path: Path to a raw disk image (e.g. ``.dd`` file).

    Returns:
        A list of ``Partition`` instances representing the partitions
        found in the image. If no partitions are found or an error
        occurs, the list will be empty.
    """
    try:
        result = subprocess.run([
            "mmls", image_path
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    partitions: List[Partition] = []
    # Regular expression to match partition table lines
    # Example line: "000:  0000002048  0009764863  0009762816  NTFS (0x07)"
    partition_re = re.compile(
        r"^\s*(\d+):\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+(.*)$")
    for line in result.stdout.splitlines():
        m = partition_re.match(line)
        if m:
            index = int(m.group(1))
            start = int(m.group(2), 10)
            end = int(m.group(3), 10)
            length = int(m.group(4), 10)
            desc = m.group(5).strip()
            offset_bytes = start * 512
            partitions.append(Partition(
                index=index,
                start_sector=start,
                end_sector=end,
                length=length,
                description=desc,
                offset=offset_bytes
            ))
    return partitions


def mount_partition_linux(image_path: str, partition: Partition, mount_point: str) -> bool:
    """Attempt to mount a partition from a disk image on Linux in read‑only mode.

    Uses the system ``mount`` command with ``loop`` and ``offset``
    options to map the specified partition into the filesystem. The
    caller is responsible for ensuring that ``mount`` is available and
    that the process has sufficient privileges. This function will
    create the mount point directory if it does not already exist.

    Args:
        image_path: Path to the disk image (``.dd`` file).
        partition: The ``Partition`` object to mount.
        mount_point: Directory where the filesystem should be mounted.

    Returns:
        True if the mount operation succeeded, False otherwise.
    """
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    os.makedirs(mount_point, exist_ok=True)
    cmd = [
        "mount",
        "-o",
        f"ro,loop,offset={partition.offset}",
        image_path,
        mount_point,
    ]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def unmount(mount_point: str) -> bool:
    """Unmount a previously mounted filesystem.

    Simply invokes ``umount`` on the given mount point. Returns
    True on success, False on failure. This function does not attempt
    to determine whether the target is actually mounted.

    Args:
        mount_point: The mount point to unmount.

    Returns:
        True if the unmount succeeded, False otherwise.
    """
    try:
        subprocess.run(["umount", mount_point], check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def extract_partition_to_directory(image_path: str, partition: Partition, dest_dir: str) -> bool:
    """Extract a partition from a disk image to a directory using pytsk3.

    On platforms where mounting with the system ``mount`` command is
    unavailable (e.g. Windows) or where the current process does not
    have sufficient privileges, this function can be used as a
    fallback. It reads the filesystem through TSK's Python bindings
    and recursively copies all files and directories into ``dest_dir``.

    Args:
        image_path: Path to the disk image file.
        partition: Partition information with a byte offset.
        dest_dir: Destination directory for extracted files.

    Returns:
        True if extraction completed successfully, False otherwise.
    """
    if pytsk3 is None:
        raise ImportError("pytsk3 is required for extraction mode but is not installed.")
    if not os.path.isfile(image_path):
        raise FileNotFoundError(f"Image not found: {image_path}")
    os.makedirs(dest_dir, exist_ok=True)
    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img, offset=partition.offset // 512)
    except Exception as e:
        print(f"Error opening filesystem: {e}")
        return False

    def _extract_directory(directory, dest_root):
        for entry in directory:
            # Skip '.' and '..' entries
            if entry.info.name.name in [b'.', b'..']:
                continue
            try:
                entry_name = entry.info.name.name.decode('utf-8', errors='replace')
            except Exception:
                entry_name = str(entry.info.name.name)
            dest_path = os.path.join(dest_root, entry_name)
            # Directory
            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                os.makedirs(dest_path, exist_ok=True)
                try:
                    sub_directory = entry.as_directory()
                    _extract_directory(sub_directory, dest_path)
                except Exception:
                    continue
            # File
            elif entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and entry.info.meta.size > 0:
                try:
                    with open(dest_path, 'wb') as out_f:
                        file_size = entry.info.meta.size
                        offset = 0
                        size = 1024 * 1024  # read in 1MB chunks
                        while offset < file_size:
                            available_to_read = min(size, file_size - offset)
                            data = entry.read_random(offset, available_to_read)
                            out_f.write(data)
                            offset += len(data)
                except Exception:
                    continue
            # Other file types (e.g. symlinks) are ignored

    root_dir = fs.open_dir('/')
    _extract_directory(root_dir, dest_dir)
    return True