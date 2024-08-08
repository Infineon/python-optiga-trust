REM SPDX-FileCopyrightText: 2024 2021-2024 Infineon Technologies AG
REM
REM SPDX-License-Identifier: MIT

:: Downloads all dependencies
:: 
@ECHO OFF

SET "SCRIPT_PATH=%~dp0"
SET "ZIP_EXE_PATH=C:\Program Files\7-Zip\7z.exe"

 set LIBUSB_DOWNLOAD_URL=https://github.com/libusb/libusb/releases/download/v1.0.27/libusb-1.0.27.7z

ECHO Downloading libusb library from:
ECHO %LIBUSB_DOWNLOAD_URL%

@REM rem Download libusb release
curl --silent --output %SCRIPT_PATH%\external\libusb.7z %LIBUSB_DOWNLOAD_URL%

@REM rem Extract files
ECHO Extract libusb library archive:
"%ZIP_EXE_PATH%" x -bb0 -o%SCRIPT_PATH%\external\libusb %SCRIPT_PATH%\external\libusb.7z

@REM rem Remove archive file
ECHO Delete libusb library archive
del %SCRIPT_PATH%\external\libusb.7z

ECHO libusb library installation successful