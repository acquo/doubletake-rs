@echo off
rem Mirror the desktop to the TV with the Rust doubletake-rs build.
rem Uses the release build (debug builds are 10-70x slower for video).
rem Usage: mirror_tv.bat [host] [--pair]
setlocal
cd /d "%~dp0"
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=192.168.1.107"
cargo run --release -p dt-capture --example mirror_desktop -- %TARGET% 7000 %2 %3 %4 %5
