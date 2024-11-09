
@echo off
start /B powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "cd 'C:\Path\To\YourDjangoProject' ; & 'C:\Path\To\Python\python.exe' manage.py runserver"
