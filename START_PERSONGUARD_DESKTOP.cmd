@echo off
set "PERSONGUARD_EXE=%~dp0desktop\artifacts\win-x64\PersonGuard.exe"
if not exist "%PERSONGUARD_EXE%" (
  echo PersonGuard.exe not found. Run build-desktop.ps1 first.
  pause
  exit /b 1
)
start "" "%PERSONGUARD_EXE%"
