@echo off
echo ========================================================
echo  Starting SentinelStream SIEM
echo ========================================================

cd sentinelstream
if not exist "target\sentinel-stream.jar" (
    echo [ERROR] target\sentinel-stream.jar not found. Please run build.bat first.
    cd ..
    exit /b 1
)

java -jar target\sentinel-stream.jar
cd ..
