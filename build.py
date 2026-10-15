"""
TinyAV Standalone Packaging Script
Builds a click-and-run standalone Windows executable and portable ZIP release.
No Python installation is required by end users to run the resulting application.
"""

import os
import shutil
import subprocess
import sys
import zipfile


def main():
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print("=" * 65)
    print("           TinyAV - Standalone Windows Release Builder           ")
    print("=" * 65)

    # 1. Ensure pyinstaller is available
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__} detected.")
    except ImportError:
        print("[!] PyInstaller is not installed. Installing via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # 2. Clean previous build artifacts
    print("\n[*] Cleaning previous build artifacts...")
    for folder in ("build", "dist"):
        folder_path = os.path.join(project_root, folder)
        if os.path.isdir(folder_path):
            try:
                shutil.rmtree(folder_path)
                print(f"    - Removed {folder}/")
            except Exception as e:
                print(f"    - Notice: Could not completely remove {folder}/: {e}")

    # 3. Execute PyInstaller
    spec_file = os.path.join(project_root, "TinyAV.spec")
    if not os.path.isfile(spec_file):
        print(f"[ERROR] Spec file not found: {spec_file}")
        sys.exit(1)

    print(f"\n[*] Compiling standalone application using {spec_file}...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        spec_file,
        "--clean",
        "--noconfirm",
    ]

    ret = subprocess.call(cmd)
    if ret != 0:
        print(f"\n[ERROR] PyInstaller build failed with exit code {ret}.")
        sys.exit(ret)

    dist_dir = os.path.join(project_root, "dist", "TinyAV")
    exe_path = os.path.join(dist_dir, "TinyAV.exe")

    if not os.path.isfile(exe_path):
        print(f"\n[ERROR] Built executable not found at: {exe_path}")
        sys.exit(1)

    size_mb = os.path.getsize(exe_path) / (1024 * 1024)
    print(f"\n[OK] Standalone executable created successfully!")
    print(f"    - Path: {exe_path}")
    print(f"    - Binary Size: {size_mb:.2f} MB")

    # 4. Create Portable Distribution ZIP
    zip_output_path = os.path.join(project_root, "dist", "TinyAV-Portable.zip")
    print(f"\n[*] Packaging portable distribution archive...")
    with zipfile.ZipFile(zip_output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(dist_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.join("TinyAV", os.path.relpath(full_path, dist_dir))
                zf.write(full_path, rel_path)

    zip_size_mb = os.path.getsize(zip_output_path) / (1024 * 1024)
    print(f"[OK] Created Portable ZIP: {zip_output_path} ({zip_size_mb:.2f} MB)")

    print("\n" + "=" * 65)
    print(" Build Complete! Ready for end users:")
    print(f" 1. Standalone Folder : dist\\TinyAV\\TinyAV.exe")
    print(f" 2. Portable ZIP      : dist\\TinyAV-Portable.zip")
    print("=" * 65)


if __name__ == "__main__":
    main()
