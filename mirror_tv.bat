@echo off
rem Mirror the desktop to the TV/receiver with the lumem (Rust) build.
rem Uses the release build (debug builds are 10-70x slower for video).
rem Usage: mirror_tv.bat [host] [port] [--pair] [--encoder nvenc|openh264|x264|mf] [--bitrate N]
setlocal
cd /d "%~dp0"

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=192.168.1.107"
set "PORT=%~2"
if "%PORT%"=="" set "PORT=7000"

rem x264 (and its pkg-config probe) resolve libx264 from the GStreamer runtime
rem on this machine. Set the env so both the build and the runtime DLL are found.
if exist "C:\Program Files\gstreamer\1.0\msvc_x86_64\bin" (
    set "PATH=C:\Program Files\gstreamer\1.0\msvc_x86_64\bin;%PATH%"
    set "PKG_CONFIG_PATH=C:\Program Files\gstreamer\1.0\msvc_x86_64\lib\pkgconfig"
)

cargo run --release -p lumen-capture --example mirror_desktop -- %TARGET% %PORT% %2 %3 %4 %5 %6
