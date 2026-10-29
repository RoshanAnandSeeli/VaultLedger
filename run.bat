@echo off
setlocal enabledelayedexpansion
title VaultLedger - Core Banking System

cd /d "%~dp0"

echo ======================================================================
echo    VaultLedger - Core Banking Account Lifecycle ^& Ledger System
echo ======================================================================
echo.

:: 1. Detect and configure JAVA_HOME
if not defined JAVA_HOME (
    if exist "C:\Program Files\Java\jdk-24" (
        set "JAVA_HOME=C:\Program Files\Java\jdk-24"
    ) else if exist "C:\Program Files\Java\jdk-21" (
        set "JAVA_HOME=C:\Program Files\Java\jdk-21"
    ) else if exist "C:\Program Files\Java\jdk-17" (
        set "JAVA_HOME=C:\Program Files\Java\jdk-17"
    )
)

if defined JAVA_HOME (
    set "PATH=%JAVA_HOME%\bin;%PATH%"
    echo [INFO] Using Java Home: %JAVA_HOME%
) else (
    echo [INFO] Using system Java from PATH
)

:: 2. Detect and configure Maven
where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\apache-maven-3.9.9\bin" (
        set "PATH=%LOCALAPPDATA%\Programs\apache-maven-3.9.9\bin;%PATH%"
    )
)

where mvn >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Apache Maven was not found in PATH or at %LOCALAPPDATA%\Programs\apache-maven-3.9.9\bin
    echo Please install Maven or add it to your PATH.
    echo.
    pause
    exit /b 1
)

:: 3. Execute requested target or launch application
if /i "%~1"=="test" (
    echo [INFO] Running automated test suite...
    echo.
    call mvn test
) else if /i "%~1"=="clean" (
    echo [INFO] Cleaning project build artifacts...
    echo.
    call mvn clean
) else (
    echo [INFO] Starting JavaFX Application...
    echo.
    call mvn javafx:run
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ======================================================================
    echo [ERROR] Execution failed with exit code %ERRORLEVEL%.
    echo ======================================================================
    pause
    exit /b %ERRORLEVEL%
)

endlocal
