import os
from typing import Set

# Common Windows and OS metadata / system-locked files that should never be scanned
IGNORED_FILE_NAMES: Set[str] = {
    "desktop.ini",
    "thumbs.db",
    "ehthumbs.db",
    "ehthumbs_vista.db",
    ".ds_store",
    "icon\r",
    "ntuser.dat",
    "ntuser.dat.log",
    "ntuser.dat.log1",
    "ntuser.dat.log2",
    "ntuser.ini",
    "usrclass.dat",
    "usrclass.dat.log",
    "usrclass.dat.log1",
    "usrclass.dat.log2",
    "bootfont.bin",
    "bootsect.bak",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "dumpstack.log",
    "dumpstack.log.tmp",
}

# Browser incomplete downloads, generic temp files, and quarantine files to ignore until final
TEMP_EXTENSIONS: Set[str] = {
    ".crdownload",   # Google Chrome, Microsoft Edge, Brave, Vivaldi
    ".tmp",          # Generic temp files
    ".part",         # Mozilla Firefox
    ".partial",      # Internet Explorer / wget
    ".downloading",  # Torrent clients / generic downloaders
    ".opdownload",   # Opera browser
    ".quarantine",   # TinyAV quarantine files
    ".!ut",          # uTorrent
    ".download",     # Safari / Chrome Mac / generic
    ".temp",
}

# Directories to ignore during recursive filesystem traversal (metadata / caches / system volume)
IGNORED_DIR_NAMES: Set[str] = {
    "__macosx",
    ".git",
    ".svn",
    ".vs",
    ".vscode",
    "node_modules",
    "$recycle.bin",
    "system volume information",
    "$windows.~bt",
    "$windows.~ws",
}


def should_skip_file(file_path: str) -> bool:
    """
    Returns True if the file should be skipped from scanning.
    Filters out OS metadata files like desktop.ini and thumbs.db,
    Office temporary lock files (~$...), and in-progress browser downloads.
    """
    if not file_path:
        return True

    # Strip NTFS Alternate Data Stream if present (e.g. file.exe:Zone.Identifier)
    clean_path = file_path
    drive, path_tail = os.path.splitdrive(file_path)
    if ":" in path_tail:
        clean_path = drive + path_tail.split(":", 1)[0]

    base_name = os.path.basename(clean_path).lower()
    if not base_name:
        return True

    # 1. Exact match for system metadata files (e.g. desktop.ini, thumbs.db)
    if base_name in IGNORED_FILE_NAMES:
        return True

    # 2. Pattern match for desktop.ini variations or localized system files
    if base_name.startswith("desktop.ini"):
        return True

    # 3. Office temporary lock files (~$filename.ext) and hidden editor scratch files
    if base_name.startswith("~$") or base_name.startswith(".~"):
        return True

    # 4. Incomplete browser downloads and temp extensions
    _, ext = os.path.splitext(base_name)
    if ext in TEMP_EXTENSIONS:
        return True

    return False


def should_skip_dir(dir_name: str) -> bool:
    """
    Returns True if the directory name matches system volume metadata or VCS caches.
    """
    if not dir_name:
        return False
    clean = os.path.basename(dir_name.rstrip("\\/")).lower()
    return clean in IGNORED_DIR_NAMES
