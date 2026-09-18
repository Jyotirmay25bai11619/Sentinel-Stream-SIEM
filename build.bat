@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo  Building SentinelStream SIEM
echo ========================================================

cd sentinelstream

set "MVN_CMD="

:: 1. Check if mvn is in PATH
where mvn >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "MVN_CMD=mvn"
    goto :run_build
)

:: 2. Check IntelliJ IDEA Community / Ultimate Maven installations
for /d %%D in ("C:\Program Files\JetBrains\IntelliJ IDEA*") do (
    if exist "%%D\plugins\maven\lib\maven3\bin\mvn.cmd" (
        set "MVN_CMD=%%D\plugins\maven\lib\maven3\bin\mvn.cmd"
        goto :run_build
    )
)

:: 3. Check Program Files Apache Maven
for /d %%D in ("C:\Program Files\apache-maven*") do (
    if exist "%%D\bin\mvn.cmd" (
        set "MVN_CMD=%%D\bin\mvn.cmd"
        goto :run_build
    )
)

:run_build
if "%MVN_CMD%"=="" (
    echo [ERROR] Maven not found. Please install Maven or add it to PATH.
    cd ..
    exit /b 1
)

echo Using Maven: "%MVN_CMD%"
"%MVN_CMD%" clean install

set BUILD_STATUS=%ERRORLEVEL%
cd ..

if %BUILD_STATUS% equ 0 (
    echo ========================================================
    echo  Build Successful!
    echo ========================================================
) else (
    echo [ERROR] Build failed with exit code %BUILD_STATUS%.
    exit /b %BUILD_STATUS%
)
