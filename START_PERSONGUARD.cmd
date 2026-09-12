@echo off
title PersonGuard
cd /d "%~dp0"
node preview-server.mjs --open
if errorlevel 1 pause
