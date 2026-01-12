@echo off
REM =============================================================================
REM Whispera Full Build Script for Windows
REM =============================================================================

setlocal enabledelayedexpansion

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                    WHISPERA BUILD SYSTEM                       ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

set PROJECT_DIR=%~dp0
set BUILD_DIR=%PROJECT_DIR%build
set TAURI_BIN=%PROJECT_DIR%client-package-tauri\src-tauri\bin

REM Create directories
if not exist "%BUILD_DIR%\server" mkdir "%BUILD_DIR%\server"
if not exist "%BUILD_DIR%\client" mkdir "%BUILD_DIR%\client"
if not exist "%TAURI_BIN%" mkdir "%TAURI_BIN%"

echo [1/5] Building Go Server...
cd /d "%PROJECT_DIR%"
set CGO_ENABLED=0
go build -ldflags "-s -w" -o "%BUILD_DIR%\server\whispera-server.exe" .\cmd\server
if errorlevel 1 goto :error
echo √ Server built

echo [2/5] Building Go Client...
go build -ldflags "-s -w" -o "%BUILD_DIR%\client\whispera-client.exe" .\cmd\client
if errorlevel 1 goto :error
echo √ Client built

echo [3/5] Copying to Tauri bin (both naming conventions)...
copy /Y "%BUILD_DIR%\client\whispera-client.exe" "%TAURI_BIN%\whispera-go-client.exe" >nul
copy /Y "%BUILD_DIR%\client\whispera-client.exe" "%TAURI_BIN%\whispera-go-client-x86_64-pc-windows-msvc.exe" >nul
echo √ Client copied to Tauri

echo [4/5] Copying Web Panel...
if exist "%PROJECT_DIR%\web" (
    xcopy /E /I /Y "%PROJECT_DIR%\web" "%BUILD_DIR%\server\web" >nul
    echo √ Web panel copied
)

echo [5/5] Building Tauri Client...
where cargo >nul 2>&1
if %errorlevel%==0 (
    cd /d "%PROJECT_DIR%\client-package-tauri"
    call npm install 2>nul
    call npm run tauri build 2>nul
    if %errorlevel%==0 (
        echo √ Tauri built
        echo.
        echo Tauri installer: client-package-tauri\src-tauri\target\release\bundle\
    ) else (
        echo ! Tauri build skipped or failed
    )
) else (
    echo ! Cargo not found, skipping Tauri build
)

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                    BUILD COMPLETE!                            ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.
echo Server: %BUILD_DIR%\server\whispera-server.exe
echo Client: %BUILD_DIR%\client\whispera-client.exe
echo Tauri:  %TAURI_BIN%\whispera-go-client.exe
echo.
echo To build Tauri manually:
echo   cd client-package-tauri
echo   npm run tauri build
echo.

goto :end

:error
echo.
echo Build failed!
exit /b 1

:end
cd /d "%PROJECT_DIR%"
endlocal
