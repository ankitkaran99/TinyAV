# TinyAV 🛡️
### Lightweight ClamAV Antivirus Companion & System Tray Utility for Windows 10/11

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![ClamAV 1.0+](https://img.shields.io/badge/ClamAV-1.0+-green.svg)](https://www.clamav.net/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg)](https://www.microsoft.com/windows)
[![Tests Passing](https://img.shields.io/badge/tests-25%20passed-success.svg)](#running-unit-tests)

**TinyAV** is a lightweight, responsive desktop antivirus companion and system tray utility for Windows that wraps the open-source **ClamAV** engine (`clamd`, `clamscan`, and `freshclam`).

It provides modern Windows integration—including context menu scanning, USB drive auto-detection, real-time folder monitoring, scheduled signature updates, one-click ClamAV configuration generation, and in-place binary upgrades from official Cisco-Talos GitHub releases—without the heavy overhead or system slowdown of invasive kernel minifilter drivers.

---

## Table of Contents
- [Features](#features)
  - [1. Scanning & Engine Capabilities](#1-scanning--engine-capabilities)
  - [2. Real-Time Directory Monitoring](#2-real-time-directory-monitoring)
  - [3. Removable Storage & USB Auto-Detection](#3-removable-storage--usb-auto-detection)
  - [4. Threat Mitigation & Quarantine Vault](#4-threat-mitigation--quarantine-vault)
  - [5. One-Click ClamAV Configuration Generator](#5-one-click-clamav-configuration-generator)
  - [6. Virus Definition Signatures Updater](#6-virus-definition-signatures-updater)
  - [7. ClamAV Engine Binary Updater](#7-clamav-engine-binary-updater)
  - [8. Windows Shell & System Tray Integration](#8-windows-shell--system-tray-integration)
- [Architecture & Design](#architecture--design)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation & Quick Start](#installation--quick-start)
- [Setup & Configuration Guide](#setup--configuration-guide)
  - [Step 1: Install ClamAV](#step-1-install-clamav)
  - [Step 2: Auto-Generate Optimized Configuration Files](#step-2-auto-generate-optimized-configuration-files)
  - [Step 3: Update Virus Signatures](#step-3-update-virus-signatures)
  - [Step 4: Enable Windows Explorer Context Menu (Optional)](#step-4-enable-windows-explorer-context-menu-optional)
  - [Step 5: Configure Real-Time Folder Monitoring (Optional)](#step-5-configure-real-time-folder-monitoring-optional)
- [Packaging Standalone Executable (PyInstaller)](#packaging-standalone-executable-pyinstaller)
- [Running Unit Tests](#running-unit-tests)
- [License](#license)

---

## Features

### 1. Scanning & Engine Capabilities
- **Hybrid Engine Integration**:
  - Automatically queries a local `clamd.exe` daemon over TCP (`127.0.0.1:3310`) for sub-second, memory-cached file scans.
  - Seamlessly falls back to `clamscan.exe` CLI subprocess scanning if `clamd` is offline or not installed.
  - Instant scan cancellation: terminates active scan threads and immediately kills background scan subprocesses.
- **Multiple Scanning Scopes**:
  - **Custom Files & Directories**: Intuitive pickers for single files or recursive folder trees.
  - **Whole Drive**: Select any mounted fixed or removable partition (or "All fixed drives").
  - **Running Process Files**: Inspects running Windows processes via `psutil`, resolves active binary paths and loaded DLL modules on disk, and scans them.
  - **Explorer Right-Click Quick Scan**: Right-click any file or folder in Windows Explorer and select **Scan with ClamAV** to launch a compact scanning dialog.

### 2. Real-Time Directory Monitoring
- **Configurable Directory Watcher**:
  - Monitors high-risk directories (e.g., your `Downloads` folder, `Desktop`, or custom paths) via `watchdog`.
  - Automatically triggers on-demand scans whenever a newly downloaded file is saved to disk.
  - **Smart Browser Handling**: Automatically ignores transient partial download files (`.crdownload`, `.tmp`, `.part`) until downloads are fully flushed and finalized.
  - **Auto-Quarantine Option**: Neutralizes threats automatically when detected in watched directories and delivers unobtrusive Windows system tray notifications.

### 3. Removable Storage & USB Auto-Detection
- **Native Win32 Message Loop**:
  - Monitors `WM_DEVICECHANGE` (`DBT_DEVICEARRIVAL`) hardware events via a dedicated background window.
  - Automatically debounces duplicate mount events across Windows volume arrivals.
- **Per-Device Preferences**:
  - Displays a non-modal prompt upon drive insertion:
    - **Scan Now**: Immediately scans the attached storage drive.
    - **Always Scan**: Stores a persistent preference indexed by the hardware volume serial number in `%LOCALAPPDATA%\TinyAV\config.json`. Every subsequent insertion scans automatically without prompting.
    - **Ignore**: Dismisses the notification.

### 4. Threat Mitigation & Quarantine Vault
- **Action Decisions**: Choose to **Quarantine**, **Delete**, or **Ignore** detections directly from scan reports.
- **Isolated Storage**: Threats are safely quarantined in `%LOCALAPPDATA%\TinyAV\Quarantine` with sanitized filenames (`.quar`).
- **Metadata Tracking**: Every item stores a companion `.json` manifest preserving original file path, threat name, SHA-256 hash, and quarantine timestamp.
- **Safe Restoration**: Non-destructive restore to original locations with automatic collision prevention.

### 5. One-Click ClamAV Configuration Generator
- **Solves ClamAV Fresh-Install Errors**:
  - By default, ClamAV Windows releases ship with sample files (`.sample`) that contain an un-commented `Example` directive and point to missing directories, causing `freshclam returned code 2: ERROR: Can't open/parse the config file`.
  - TinyAV provides a one-click button: **Auto-Generate Conf Files** in both the **Settings** and **Updates & Signatures** tabs.
  - Automatically creates the required `<ClamAV>\database` folder.
  - Generates ready-to-use, optimized `freshclam.conf` and `clamd.conf` files with optimal timeouts, database mirrors, certs paths, and memory limits.
  - Automatically escalates via Windows UAC if ClamAV is installed under a protected path such as `C:\Program Files\ClamAV`.

### 6. Virus Definition Signatures Updater
- **Automated freshclam Scheduling**:
  - Wraps `freshclam.exe` using `APScheduler` background intervals.
  - Configurable update intervals (**1h, 2h, 4h, 6h, 12h, 24h**, or custom hours) in both the **Updates** and **Settings** tabs.
  - Changing intervals dynamically updates the active schedule without requiring an application restart.
  - Manual **Update Definitions Now** button with live terminal-like activity output.

### 7. ClamAV Engine Binary Updater
- **Cisco-Talos GitHub Releases Integration**:
  - Directly queries the official [Cisco-Talos/clamav Releases API](https://github.com/Cisco-Talos/clamav/releases).
  - Automatically checks current engine version against the latest GitHub release.
- **In-Place Portable Upgrades (ZIP)**:
  - One-click **Update Engine (Portable ZIP)** downloads the system architecture-matched portable archive (`.win.x64.zip`, `.win.arm64.zip`, or `.win.win32.zip`).
  - Extracts and updates the binaries in-place while **strictly preserving** your existing configuration (`freshclam.conf`, `clamd.conf`) and downloaded virus databases (`database/`).
- **Official Windows Installer (MSI)**:
  - One-click **Download Installer (MSI)** downloads the official installer to your `Downloads` folder and launches Windows setup.
- **Live Transfer Status**: Real-time progress bar displaying download percentage, transferred megabytes, and connection status.

### 8. Windows Shell & System Tray Integration
- **System Tray Presence**: Runs in the background with `pystray`. Closing the application window minimizes to the tray (`root.withdraw()`).
- **Dynamic Shield Icons**: Visual state representation in the notification area:
  - 🟢 **Green Shield**: Idle & Protected
  - 🔵 **Blue Shield**: Scan in Progress
  - 🔷 **Cyan Shield**: Updating Definitions or Binaries
  - 🔴 **Red Shield**: Threat Detected
- **Windows Explorer Right-Click Menu**: Elevates via UAC only when registering or unregistering registry keys (`HKEY_CLASSES_ROOT`), allowing standard non-admin daily execution.

---

## Architecture & Design

TinyAV follows a decoupled, thread-safe architecture:

```
┌────────────────────────────────────────────────────────┐
│                   Tkinter Main Thread                  │
│       (MainWindow, ScannerTab, UpdatesTab, etc.)       │
└───────────────────────────▲────────────────────────────┘
                            │ Queue Events (root.after polling)
┌───────────────────────────┴────────────────────────────┐
│                  Thread-Safe ui_queue                  │
└───────▲──────────────▲───────────────▲──────────────▲──┘
        │              │               │              │
┌───────┴──────┐┌──────┴──────┐┌───────┴──────┐┌──────┴──────┐
│  ScanEngine  ││FolderWatcher││ DriveWatcher ││UpdateManager│
│  clamd/CLI   ││ (watchdog)  ││ (Win32 Loop) ││(freshclam / │
│ WorkerThread ││Daemon Thread││Daemon Thread ││GitHub API)  │
└──────────────┘└─────────────┘└──────────────┘└─────────────┘
```

- **Thread-Safe Queue Marshalling**: Background tasks (scanning, definition downloads, binary upgrades, USB monitors) communicate back to Tkinter via `queue.Queue`.
- **Zero Kernel Drivers**: Operates entirely in user space. System stability and performance remain completely unaffected.
- **Process Isolation**: External utilities (`clamscan`, `freshclam`, `msiexec`) run as isolated subprocesses with console window suppression (`CREATE_NO_WINDOW`).

---

## Project Structure

```
TinyAV/
├── app/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── binary_updater.py    # Cisco-Talos GitHub releases engine binary updater
│   │   ├── config.py            # JSON config manager (%LOCALAPPDATA%\TinyAV\config.json)
│   │   ├── config_generator.py  # Auto-generator for freshclam.conf & clamd.conf
│   │   ├── engine.py            # Hybrid ClamAV engine (clamd socket + clamscan CLI fallback)
│   │   ├── folder_watcher.py    # Real-time directory monitor for Downloads & custom folders
│   │   ├── logger.py            # Rotating file logger (%LOCALAPPDATA%\TinyAV\logs\tinyav.log)
│   │   ├── process_scanner.py   # Active Windows process binary & DLL module collector
│   │   ├── quarantine.py        # Isolated quarantine vault with JSON metadata tracking
│   │   └── updater.py           # freshclam wrapper & APScheduler definition updates
│   ├── platform_win/
│   │   ├── __init__.py
│   │   ├── context_menu.py      # Windows Explorer right-click integration with UAC elevation
│   │   ├── drive_watcher.py     # Native Win32 WM_DEVICECHANGE removable drive listener
│   │   └── win_drives.py        # Windows volume inspection and drive letter resolver
│   └── ui/
│       ├── __init__.py
│       ├── icons.py             # Dynamic PIL shield state icons for system tray
│       ├── main_window.py       # Master Tkinter window and event processing queue
│       ├── quick_scan_dialog.py # Standalone scan window & USB drive prompt dialog
│       ├── tray.py              # Pystray background system tray manager
│       └── tabs/
│           ├── __init__.py
│           ├── quarantine_tab.py# Quarantine vault table, file restoration & deletion
│           ├── scan_tab.py      # Scan configuration, progress gauges & detection table
│           ├── settings_tab.py  # Paths, scheduled intervals, watched folders & Explorer keys
│           └── update_tab.py    # Virus signatures & ClamAV binary updates dashboard
├── tests/
│   ├── __init__.py
│   ├── test_binary_updater.py
│   ├── test_cancellation_and_settings.py
│   ├── test_config_generator.py
│   ├── test_engine_parser.py
│   ├── test_folder_watcher.py
│   ├── test_process_scanner.py
│   ├── test_quarantine.py
│   └── test_settings.py
├── main.py                      # Main application entry point & CLI handler
├── requirements.txt             # Python dependencies
└── README.md                    # Project documentation
```

---

## Prerequisites

- **Operating System**: Windows 10 or Windows 11 (64-bit x64 or ARM64).
- **Python**: Python 3.10 or newer (tested with Python 3.10 – 3.14).
- **ClamAV**: Any official release of ClamAV for Windows.

---

## Installation & Quick Start

1. **Clone or extract TinyAV**:
   ```powershell
   git clone https://github.com/ankitkaran99/TinyAV.git
   cd TinyAV
   ```

2. **Create a virtual environment (recommended)**:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

4. **Launch TinyAV**:
   ```powershell
   python main.py
   ```

   To start TinyAV directly minimized into the system tray:
   ```powershell
   python main.py --minimized
   ```

---

## Setup & Configuration Guide

### Step 1: Install ClamAV
If ClamAV is not already installed on your system, install it via your preferred method:
- **Chocolatey** (Recommended):
  ```powershell
  choco install clamav
  ```
- **Scoop**:
  ```powershell
  scoop install clamav
  ```
- **Official Installer / ZIP**:
  Download from [clamav.net/downloads](https://www.clamav.net/downloads) or use TinyAV's built-in binary updater!

### Step 2: Auto-Generate Optimized Configuration Files
Fresh ClamAV installations lack valid configuration files. TinyAV fixes this in one click:
1. Open TinyAV and navigate to the **Settings** or **Updates & Signatures** tab.
2. Click **Auto-Generate Conf Files**.
3. TinyAV will detect your installation path (e.g. `C:\tools\clamav`), create the `database` directory, and generate optimized `freshclam.conf` and `clamd.conf` files.

### Step 3: Update Virus Signatures
1. In the **Updates & Signatures** tab, click **Update Definitions Now**.
2. TinyAV will run `freshclam.exe` in the background and stream download progress into the activity box.
3. Configure your desired automatic update interval (e.g., *Every 4 hours*) and click **Apply Schedule**.

### Step 4: Enable Windows Explorer Context Menu (Optional)
To add **"Scan with ClamAV"** to your right-click context menu in Windows Explorer:
1. Go to the **Settings** tab.
2. Under **Windows Explorer Integration**, click **Register Context Menu (UAC)**.
3. Approve the Windows UAC elevation prompt.
4. You can now right-click any file, folder, or drive in Windows Explorer and scan it instantly.

### Step 5: Configure Real-Time Folder Monitoring (Optional)
To automatically scan files when downloaded:
1. Go to the **Settings** tab > **Real-Time Directory Monitoring**.
2. Click **Add Downloads Folder** (or browse to any custom folder).
3. Check **Enable real-time folder scanning**.
4. Check **Auto-quarantine threats detected in watched folders** if you want detected threats neutralized immediately without manual intervention.
5. Click **Save Settings**.

---

## Packaging Standalone Executable (PyInstaller)

TinyAV is architected to compile into a standalone Windows `.exe`:

```powershell
pip install pyinstaller
pyinstaller --noconsole --name TinyAV --icon app/assets/icon.ico main.py
```

When frozen with PyInstaller, TinyAV detects `sys.frozen` automatically and adjusts registry integration commands and elevated execution parameters accordingly.

---

## Running Unit Tests

TinyAV includes comprehensive unit and integration tests covering the hybrid engine parser, cancellation behavior, quarantine vaults, folder monitoring, configuration generators, and GitHub binary updaters:

```powershell
python -m pytest -v
```

Output:
```
============================= test session starts =============================
collected 25 items

tests/test_binary_updater.py::test_system_arch PASSED                    [  4%]
tests/test_binary_updater.py::test_parse_version_tuple PASSED            [  8%]
tests/test_binary_updater.py::test_apply_zip_update_direct_preserves_configs_and_db PASSED [ 12%]
tests/test_binary_updater.py::test_check_for_updates_mocked PASSED       [ 16%]
tests/test_cancellation_and_settings.py::test_engine_cancel_active_scan PASSED [ 20%]
tests/test_cancellation_and_settings.py::test_engine_cancel_when_no_active_proc PASSED [ 24%]
tests/test_cancellation_and_settings.py::test_scan_excludes_quarantine_directory PASSED [ 28%]
tests/test_config_generator.py::test_generate_configs_direct_in_temp_dir PASSED [ 32%]
tests/test_config_generator.py::test_generate_configs_invalid_dir PASSED [ 36%]
tests/test_config_generator.py::test_high_level_generate_configs PASSED  [ 40%]
tests/test_engine_parser.py::test_parse_clamscan_line_ok PASSED          [ 44%]
tests/test_engine_parser.py::test_parse_clamscan_line_found PASSED       [ 48%]
tests/test_engine_parser.py::test_parse_clamscan_line_error PASSED       [ 52%]
tests/test_engine_parser.py::test_parse_clamscan_unrelated_lines PASSED  [ 56%]
tests/test_engine_parser.py::test_engine_mode_unavailable_when_no_binaries PASSED [ 60%]
tests/test_folder_watcher.py::test_folder_watcher_temp_file_filter PASSED [ 64%]
tests/test_folder_watcher.py::test_folder_watcher_scan_and_auto_quarantine PASSED [ 68%]
tests/test_folder_watcher.py::test_folder_watcher_quarantine_exclusion PASSED [ 72%]
tests/test_process_scanner.py::test_collect_process_files PASSED         [ 76%]
tests/test_quarantine.py::test_quarantine_lifecycle PASSED               [ 80%]
tests/test_quarantine.py::test_quarantine_restore_collision PASSED       [ 84%]
tests/test_quarantine.py::test_quarantine_restore_multiple_collisions PASSED [ 88%]
tests/test_settings.py::test_default_config PASSED                       [ 92%]
tests/test_settings.py::test_update_and_save_config PASSED               [ 96%]
tests/test_settings.py::test_corrupted_config_fallback PASSED            [100%]

============================= 25 passed in 13.54s =============================
```

---

## License

This project is released under the **MIT License**. ClamAV is maintained by Cisco Talos and licensed under GPLv2.