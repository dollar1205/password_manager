"""
Build script for Password Manager
Creates a standalone .exe file
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    print("=" * 50)
    print("  Building Password Manager .exe")
    print("=" * 50)
    print()
    
    # Install dependencies
    print("Installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    print()
    
    # Find customtkinter path
    import customtkinter
    ctk_path = Path(customtkinter.__file__).parent
    
    print(f"CustomTkinter path: {ctk_path}")
    print()
    print("Building executable...")
    print()
    
    # Build with PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", "PasswordManager",
        "--add-data", f"{ctk_path};customtkinter/",
        "gui_app.py"
    ]
    
    subprocess.run(cmd, check=True)
    
    print()
    print("=" * 50)
    print("  Build complete!")
    print("  Executable: dist/PasswordManager.exe")
    print("=" * 50)

if __name__ == "__main__":
    main()
