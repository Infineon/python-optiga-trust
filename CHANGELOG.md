# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.4.1 (2024-08-27)

### Changed
- Migrated from .reuse/dep5 to REUSE.toml

### Fixed
- Added optigatrust-libusb-win-amd64 library


## 1.4.0 (2024-08-08)

### Added
- [Reuse](https://reuse.software/) compliancy
- [Download script](extras/optiga-trust-m/download_libusb_windows.bat) for the download of LibUSB library and header for Windows

### Changed
- Moved to optiga-trust-m host library v5.x.x
- Migrated Visual Studio project for host library build to Visual Studio 2022
- Folder structure adapted to best practices (Pitchfork layout)
- Improved documentation
- Improved code formatting both for C and Python

### Fixed
- Cleaned up logging output
