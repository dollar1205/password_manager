@echo off
echo ========================================
echo   Building Password Manager .exe
echo ========================================
echo.

pip install -r requirements.txt

echo.
echo Building executable...
echo.

pyinstaller --noconfirm --onefile --windowed ^
    --name "PasswordManager" ^
    --icon "NONE" ^
    --add-data "C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python*\Lib\site-packages\customtkinter;customtkinter/" ^
    gui_app.py

echo.
echo ========================================
echo   Build complete!
echo   Executable: dist\PasswordManager.exe
echo ========================================
pause
