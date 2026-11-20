@echo off
rem Jalankan MyDNS dari folder proyek ini.
rem Tambahkan folder ini ke PATH supaya cukup mengetik: mydns
setlocal
set "BIN=%~dp0mydns.exe"
if not exist "%BIN%" set "BIN=%~dp0target\release\mydns.exe"
if not exist "%BIN%" set "BIN=%~dp0target\debug\mydns.exe"
if not exist "%BIN%" (
  echo Binary belum dibangun. Jalankan dulu: cargo build --release
  exit /b 1
)
"%BIN%" %*
