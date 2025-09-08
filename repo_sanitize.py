#!/usr/bin/env python3
import argparse, os, re, sys, shutil
from pathlib import Path

# ----- Configure tokens (case-insensitive, whole words where sensible) -----
BANNED_WORDS = [
    r"enhance", r"enhanced", r"enhancement",
    r"fix", r"fixed", r"fixes",
    r"final", r"finalized", r"finalise", r"finalized", r"finalizing"
]
# For filenames, we also catch common separators like - _ and compress them later.
FILENAME_PAT = re.compile(r"(?i)(" + r"|".join(BANNED_WORDS) + r")")

# For content: match whole words (avoid nuking legit tokens like '' in code types).
CONTENT_PAT = re.compile(r"(?i)\b(" + r"|".join(BANNED_WORDS) + r")\b")

# File types to process text-wise
TEXT_EXTS = {".py", ".md", ".txt", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".json", ".rst", ".sh", ".ps1", ".bat"}

# Paths to skip entirely
SKIP_DIRS = {".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__", "node_modules", "dist", "build", "venv", ".venv"}

def is_text_file(p: Path) -> bool:
    return p.suffix.lower() in TEXT_EXTS

def iter_repo_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        # prune skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(("dfw_env", "env", ".mypy_cache"))]
        for fn in filenames:
            yield Path(dirpath) / fn

def sanitize_docstrings_and_comments_py(text: str) -> str:
    """
 Only scrub:
 - hash comments (# ...)
 - docstrings (triple quotes)
 Leave code identifiers alone.
"""
    out_lines = []
    in_doc = False
    doc_delim = None
    i = 0
    lines = text.splitlines(keepends=False)
    while i < len(lines):
        line = lines[i]
        # Detect start/end of docstring (""" or ''')
 if not in_doc:
 m = re.search(r'([\'"]{3})', line)
 if m:
 # entering docstring
 in_doc = True
 doc_delim = m.group(1)
 # scrub from the delimiter to end of line
 prefix, delim, rest = line.partition(doc_delim)
 rest = CONTENT_PAT.sub("", rest)
 rest = re.sub(r"\s{2,}", " ", rest).rstrip()
 out_lines.append(prefix + delim + rest)
 else:
 # scrub comments only
 if "#" in line:
 head, hash_, tail = line.partition("#")
 tail = CONTENT_PAT.sub("", tail)
 tail = re.sub(r"\s{2,}", " ", tail).rstrip()
 out_lines.append(head + hash_ + tail)
 else:
 out_lines.append(line)
 else:
 # in docstring until we find matching delimiter
 if doc_delim in line:
 pre, delim, post = line.partition(doc_delim)
 pre = CONTENT_PAT.sub("", pre)
 pre = re.sub(r"\s{2,}", " ", pre).rstrip()
 out_lines.append(pre + delim + post)
 in_doc = False
 doc_delim = None
 else:
 line2 = CONTENT_PAT.sub("", line)
 line2 = re.sub(r"\s{2,}", " ", line2).rstrip()
 out_lines.append(line2)
 i += 1

 return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")

def sanitize_text_generic(text: str) -> str:
 text2 = CONTENT_PAT.sub("", text)
 # collapse doubled spaces created by removals
 text2 = re.sub(r"[ ]{2,}", " ", text2)
 # tidy leftover " - " or " _ " artifacts
 text2 = re.sub(r"[ _-]{2,}", " ", text2)
 return text2

def process_file(path: Path, apply: bool) -> bool:
 if not is_text_file(path):
 return False
 try:
 data = path.read_text(encoding="utf-8", errors="ignore")
 except Exception:
 return False

 if path.suffix.lower() == ".py":
 new = sanitize_docstrings_and_comments_py(data)
 else:
 new = sanitize_text_generic(data)

 if new != data:
 if apply:
 path.write_text(new, encoding="utf-8")
 return True
 return False

def safe_rename(path: Path, apply: bool) -> Path:
 name = path.name
 new_name = FILENAME_PAT.sub("", name)
 # collapse duplicate separators or leftover dashes/underscores
 new_name = re.sub(r"[-_]{2,}", "-", new_name)
 new_name = new_name.strip("-_ ")
 # Avoid empty names
 if not new_name:
 new_name = "renamed"
 if new_name != name:
 new_path = path.with_name(new_name)
 if apply:
 try:
 path.rename(new_path)
 except Exception:
 # if rename fails (case-only rename on Windows), do a temp then move
 tmp = path.with_name(new_name + ".tmpmove")
 path.rename(tmp)
 tmp.rename(new_path)
 return new_path
 return path

def rename_walk(root: Path, apply: bool):
 # rename files first (deepest first), then directories (deepest first)
 changed = []
 all_paths = sorted([p for p in root.rglob("*") if p.exists()], key=lambda p: (-len(p.as_posix()), p.as_posix()))
 for p in all_paths:
 if any(part in SKIP_DIRS for part in p.parts):
 continue
 if p.name.startswith(".git"): # extra guard
 continue
 newp = safe_rename(p, apply)
 if newp != p:
 changed.append((p, newp))
 return changed

def main():
 ap = argparse.ArgumentParser(description="Scrub banned words from comments/docstrings and filenames.")
 ap.add_argument("--apply", action="store_true", help="Actually write changes (default is dry-run).")
 ap.add_argument("--root", default=".", help="Project root (default: current directory).")
 args = ap.parse_args()

 root = Path(args.root).resolve()
 if not root.exists():
 print(f"Root not found: {root}", file=sys.stderr)
 sys.exit(2)

 print(f"[1/2] Scanning & cleaning text files under {root} (dry-run={not args.apply})...")
 changes = 0
 for p in iter_repo_files(root):
 if process_file(p, args.apply):
 changes += 1
 print(("WROTE " if args.apply else "WOULD ") + str(p.relative_to(root)))

 print(f"[2/2] Renaming files/folders containing banned tokens...")
 renames = rename_walk(root, args.apply)
 for old, new in renames:
 print(("RENAMED " if args.apply else "WOULD RENAME ") + f"{old.relative_to(root)} -> {new.relative_to(root)}")

 print(f"\nSummary: {changes} file(s) {'modified' if args.apply else 'would be modified'}, {len(renames)} path(s) {'renamed' if args.apply else 'would be renamed'}.")

if __name__ == "__main__":
 main()
