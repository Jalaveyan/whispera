@echo off
REM =============================================================================
REM Whispera Quick Connect for Windows
REM Place your connection key in key.txt or run with: quick-connect.bat "whispera://..."
REM =============================================================================

setlocal

set KEY=%1

REM If no argument, try to read from key.txt
if "%KEY%"=="" (
    if exist "%~dp0key.txt" (
        set /p KEY=<"%~dp0key.txt"
    ) else if exist "%USERPROFILE%\.whispera\key.txt" (
        set /p KEY=<"%USERPROFILE%\.whispera\key.txt"
    ) else (
        echo.
        echo Whispera Quick Connect
        echo ======================
        echo.
        echo Usage:
        echo   quick-connect.bat "whispera://server:port?key=...^&pub=..."
        echo.
        echo Or create key.txt with your connection key
        echo.
        exit /b 1
    )
)

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                   WHISPERA QUICK CONNECT                       ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Find whispera client
set CLIENT=
if exist "%~dp0whispera-client.exe" set CLIENT=%~dp0whispera-client.exe
if exist "%~dp0whispera-go-client.exe" set CLIENT=%~dp0whispera-go-client.exe
if exist "%~dp0bin\whispera-go-client.exe" set CLIENT=%~dp0bin\whispera-go-client.exe

if "%CLIENT%"=="" (
    echo ERROR: Whispera client not found!
    echo Place whispera-client.exe in the same folder as this script.
    pause
    exit /b 1
)

echo Client: %CLIENT%
echo.
echo Connecting...
echo.

REM Start client with connection key
"%CLIENT%" -key "%KEY%"

endlocal
