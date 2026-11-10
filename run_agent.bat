@echo off
rem -----------------------------------------------------------------------------
rem run_agent.bat - ZeroWatch Windows Sentinel Agent Local Launcher
rem
rem Usage:
rem   run_agent.bat [OPTIONS]
rem
rem Options:
rem   --dev         Connect to local dev backend (http://localhost:3001/api) [Default]
rem   --prod        Connect to production backend (https://zerowatch.deepcytes.io/api)
rem   --demo        Connect to Azure demo/test backend
rem   --server URL  Connect to custom server URL
rem   --daemon      Run in background daemon mode
rem   --enroll      Force enrollment GUI frame
rem   --dashboard   Force dashboard GUI frame
rem   --test        Run local test suite (pytest)
rem   --help        Show this help message
rem
rem Examples:
rem   run_agent.bat
rem   run_agent.bat --dev
rem   run_agent.bat --server http://localhost:3001
rem   run_agent.bat --enroll
rem   run_agent.bat --test
rem -----------------------------------------------------------------------------

setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "SERVER_FLAG="
set "CUSTOM_URL="
set "EXTRA_ARGS="
set "DO_TEST=0"

:parse_args
if "%~1"=="" goto end_parse_args

if /I "%~1"=="--help" goto show_help
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="/help" goto show_help
if /I "%~1"=="/?" goto show_help

if /I "%~1"=="--test" (
    set "DO_TEST=1"
    shift
    goto parse_args
)

if /I "%~1"=="--dev" (
    set "SERVER_FLAG=--dev"
    shift
    goto parse_args
)

if /I "%~1"=="--prod" (
    set "SERVER_FLAG=--prod"
    shift
    goto parse_args
)

if /I "%~1"=="--demo" (
    set "SERVER_FLAG=--server https://zerowatch-testing.eastasia.cloudapp.azure.com"
    shift
    goto parse_args
)

if /I "%~1"=="--server" (
    set "SERVER_FLAG=--server %~2"
    shift
    shift
    goto parse_args
)

set "EXTRA_ARGS=!EXTRA_ARGS! %~1"
shift
goto parse_args

:end_parse_args

rem -- Run local test suite if requested ----------------------------------------
if "%DO_TEST%"=="1" (
    echo [TEST] Executing Sentinel Agent Windows test suite...
    py -3.11 -m pytest tests/
    exit /b %ERRORLEVEL%
)

rem Default to --dev (local) if no explicit server target was passed
if not defined SERVER_FLAG (
    set "SERVER_FLAG=--dev"
)

echo ================================================================
echo  ZeroWatch Windows Sentinel Agent Launcher
echo ================================================================
echo Mode: %SERVER_FLAG% %EXTRA_ARGS%
echo.

py -3.11 sentinel_agent.py %SERVER_FLAG% %EXTRA_ARGS%
exit /b %ERRORLEVEL%

:show_help
echo Usage: run_agent.bat [OPTIONS]
echo.
echo Options:
echo   --dev         Connect to local dev backend (http://localhost:3001/api) [Default]
echo   --prod        Connect to production backend (https://zerowatch.deepcytes.io/api)
echo   --demo        Connect to Azure demo/test backend
echo   --server URL  Connect to custom server URL
echo   --daemon      Run in background daemon mode
echo   --enroll      Force enrollment GUI frame
echo   --dashboard   Force dashboard GUI frame
echo   --test        Run local test suite (pytest)
echo   --help        Show this help message
exit /b 0
