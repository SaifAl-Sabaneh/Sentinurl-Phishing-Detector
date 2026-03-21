import os
import sys

def setup_startup():
    # 1. Get current project directory dynamically
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Locate Windows Startup folder
    startup_folder = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    batch_file_path = os.path.join(startup_folder, 'SentinURL_Automated_Retrain.bat')
    
    # 3. Create the dynamic batch file
    # We use %~dp0 logic for the batch file if it was in the same folder, 
    # but since it's in Startup, we must point to the CURRENT location of this folder.
    # We also use 'start /d' to set the working directory.
    
    batch_content = f"""@echo off
REM SentinURL Automated Retraining Trigger
REM Generated dynamically for portability
start /d "{current_dir}" /b /min pythonw automated_retrain.py
"""
    
    try:
        with open(batch_file_path, "w") as f:
            f.write(batch_content)
        print(f"[v] Successfully created Startup trigger at: {batch_file_path}")
        print(f"[v] Project Location Locked: {current_dir}")
    except Exception as e:
        print(f"[x] Failed to create Startup trigger: {e}")

if __name__ == "__main__":
    print("--- SentinURL Portability Setup ---")
    setup_startup()
    print("\n[DONE] Your system is now configured to automatically retrain on logon.")
    print("If you move this project folder, just run 'python portable_setup.py' again to update the paths.")
