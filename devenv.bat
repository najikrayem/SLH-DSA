@REM Update path as needed
cmd /k C:\QNX\qnx800\qnxsdp-env.bat
set CC=%QNX_HOST%\usr\bin\qcc

@echo off
setlocal enabledelayedexpansion

@REM TODO
for /F "tokens=1* delims==" %%a in ('set') do (
    set "value=%%b"
    set "value=!value:\=/!"
    echo %%a=!value!
)

endlocal