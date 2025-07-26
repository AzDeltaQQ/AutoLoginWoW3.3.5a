@echo off
echo Building WoW Auto-Login Program with Visual Studio...
echo.

REM Try to find Visual Studio 2022 Developer Command Prompt
set VS2022_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
set VS2019_PATH="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"

if exist %VS2022_PATH% (
    echo Using Visual Studio 2022...
    call %VS2022_PATH% -arch=x86
) else if exist %VS2019_PATH% (
    echo Using Visual Studio 2019...
    call %VS2019_PATH% -arch=x86
) else (
    echo Error: Visual Studio Developer Command Prompt not found
    echo Please install Visual Studio Community Edition
    pause
    exit /b 1
)

REM Create build directory
if not exist build mkdir build
cd build

REM Clean build directory
if exist CMakeCache.txt del CMakeCache.txt
if exist CMakeFiles rmdir /s /q CMakeFiles

REM Configure with Visual Studio
echo Configuring with Visual Studio...
cmake .. -G "Visual Studio 17 2022" -A Win32

if errorlevel 1 (
    echo Trying Visual Studio 2019...
    cmake .. -G "Visual Studio 16 2019" -A Win32
)

if errorlevel 1 (
    echo Error: CMake configuration failed
    pause
    exit /b 1
)

REM Build the project
echo.
echo Building project...
cmake --build . --config Release

if errorlevel 1 (
    echo Error: Build failed
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
echo Executable: WoWAutoLogin.exe
echo.
echo Remember to run as Administrator!
pause 