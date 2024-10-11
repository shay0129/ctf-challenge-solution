import os
import subprocess
import sys

def py_to_exe(py_file):
    print(f"Attempting to convert: {py_file}")
    
    # בדיקה אם PyInstaller מותקן
    try:
        result = subprocess.run(["pyinstaller", "--version"], capture_output=True, text=True)
        print(f"PyInstaller version: {result.stdout.strip()}")
    except FileNotFoundError:
        print("PyInstaller is not installed or not in PATH. Please install it using 'pip install pyinstaller'")
        return

    # בדיקה אם הקובץ קיים
    if not os.path.exists(py_file):
        print(f"Error: The file '{py_file}' does not exist.")
        return

    # הפעלת PyInstaller
    try:
        print("Running PyInstaller...")
        result = subprocess.run(["pyinstaller", "--onefile", "--noconsole", py_file], 
                                capture_output=True, text=True)
        print(f"PyInstaller stdout:\n{result.stdout}")
        print(f"PyInstaller stderr:\n{result.stderr}")
        
        if result.returncode == 0:
            print(f"Conversion successful. EXE file should be created in the 'dist' folder.")
        else:
            print(f"PyInstaller returned non-zero exit code: {result.returncode}")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during conversion: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python py_to_exe_converter.py <path_to_python_file>")
    else:
        py_file = sys.argv[1]
        py_to_exe(py_file)