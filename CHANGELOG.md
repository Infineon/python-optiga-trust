# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## 1.5.0 (2025-02-25)

### Added
- Support for new OPTIGA™ Trust M v3 firmware version v3.02.2564
- New CLI feature: chipinfo readout
- New CLI feature: interface parameter for interface selection
- Support for I²C via gpiod
- Example for signature creation and verification with Infineon pre-provisioned
  key pair and certificate

### Changed
- Updated documentation: 
    - Move to Infineon theme
    - Move to mikroBUS™ shields as preferred setup
    - General improvements and fixes
- Completely removed `oscrypto` from project in favor of `cryptography` package
- Updated Python package dependencies to latest versions

### Fixed
- Fixed an issue when importing a DER formatted x.509 certificate

## 1.4.3 (2024-11-29)

### Changed
- Updated optiga-trust-m module to v5.3.0
- Fixed sample preparation config
- Improve permission handling for libusb on Linux
- Improved the description and metadata of the Python package

## 1.4.2 (2024-08-29)

### Fixed
- Removed .reuse/dep5
- Cleaned setup.py
- Date of release 1.4.1 fixed

## 1.4.1 (2024-08-29)

### Changed
- Migrated from .reuse/dep5 to REUSE.toml

### Fixed
- Added optigatrust-libusb-win-amd64 library

## 1.4.0 (2024-08-08)

### Added
- [Reuse](https://reuse.software/) compliancy
- [Download script](extras/optiga-trust-m/download_libusb_windows.bat) for the
  download of LibUSB library and header for Windows

### Changed
- Moved to optiga-trust-m host library v5.x.x
- Migrated Visual Studio project for host library build to Visual Studio 2022
- Folder structure adapted to best practices (Pitchfork layout)
- Improved documentation
- Improved code formatting both for C and Python

### Fixed
- Cleaned up logging output
