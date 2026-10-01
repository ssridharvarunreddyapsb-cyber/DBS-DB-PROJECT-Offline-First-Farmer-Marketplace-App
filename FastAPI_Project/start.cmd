@echo off
cd /d "%~dp0"
rem Use the JSON-backed server so accounts created locally survive restarts
rem without requiring a separate MongoDB service.
node server.js
