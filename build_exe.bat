@echo off
echo Building SentinURL Scanner Executable...
echo This will take a few minutes. Please wait...

:: Install PyInstaller if not already installed
python -m pip install pyinstaller

:: Build the executable
python -m pyinstaller --name "SentinURL_Scanner" --onefile ^
    --add-data "models;models" ^
    --add-data "data;data" ^
    --hidden-import="catboost" ^
    --hidden-import="scikit-learn" ^
    --hidden-import="pandas" ^
    --hidden-import="numpy" ^
    --hidden-import="tldextract" ^
    --hidden-import="whois" ^
    --hidden-import="fpdf2" ^
    src\sentinurl.py

echo Build complete! The executable is located in the "dist" folder.
pause
