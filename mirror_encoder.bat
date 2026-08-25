@echo off
rem Mirror the desktop to the TV with a selectable encoder.
rem
rem Usage:
rem   mirror_encoder.bat            -> interactive menu (1-4)
rem   mirror_encoder.bat mf         -> MediaFoundation hardware (QSV/NVENC)
rem   mirror_encoder.bat 3          -> number also works (3 = x264)
rem   mirror_encoder.bat <enc> <host>
rem
rem Encoders: 1=nvenc  2=openh264  3=x264  4=mf
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "HOST=%~2"
if "%HOST%"=="" set "HOST=192.168.1.107"

set "ENC=%~1"
if not "%ENC%"=="" goto haveenc

echo Select encoder:
echo   1. nvenc     NVIDIA hardware
echo   2. openh264  CPU software
echo   3. x264      CPU software, 4:2:0 baseline
echo   4. mf        MediaFoundation hardware, QSV / NVENC
set /p "ENC=Choice [1-4]: "

:haveenc
if "!ENC!"=="1" set "ENC=nvenc"
if "!ENC!"=="2" set "ENC=openh264"
if "!ENC!"=="3" set "ENC=x264"
if "!ENC!"=="4" set "ENC=mf"

rem x264 builds against and runs with the GStreamer-bundled libx264 on this machine.
rem Set the env so a fresh build and the runtime DLL are both found.
if exist "C:\Program Files\gstreamer\1.0\msvc_x86_64\bin" (
    set "PATH=C:\Program Files\gstreamer\1.0\msvc_x86_64\bin;!PATH!"
    set "PKG_CONFIG_PATH=C:\Program Files\gstreamer\1.0\msvc_x86_64\lib\pkgconfig"
)

echo.
echo Mirroring to !HOST! with encoder [!ENC!] ...
echo If the TV asks for an AirPlay code, read it off the TV and type it here.
echo.
cargo run --release -p lumen-capture --example mirror_desktop -- !HOST! 7000 --pair --encoder !ENC! --bitrate 4000
