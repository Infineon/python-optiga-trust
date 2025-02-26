# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

from setuptools import setup, find_packages
from setuptools.command.install import install

import codecs
import sys
import os
import shutil


def _read_relative(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), "r") as fp:
        return fp.read()


def _copy_rules(target):
    rules = "src/optigatrust/rules/90-optigatrust.rules"

    if not os.path.exists(target):
        raise FileNotFoundError

    if not os.path.exists(target + os.path.sep + os.path.basename(rules)):
        shutil.copy(rules, target)


def _install_rules():
    if sys.platform.startswith("linux"):
        try:
            _copy_rules("/etc/udev/rules.d")
        except PermissionError as e:
            print("Error: Installation of udev rules failed! Install as sudo or manually.")
            print(e)
        except Exception as e:
            print("Error: Installation of udev rules failed!")
            print(e)


class _install(install):
    def run(self):
        # Installation
        install.run(self)
        # Post-install steps
        _install_rules()


def __description():
    description_file = os.path.join("src", "optigatrust", "DESCRIPTION.md")
    with open(description_file, "r", encoding="utf-8") as f:
        readme = f.read()

    return readme


def __get_version(rel_path):
    for line in _read_relative(rel_path).splitlines():
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


__name = "optigatrust"
__desc = "A ctypes based Python wrapper for the OPTIGA™ Trust M Host Library for C"
__url = "https://github.com/infineon/python-optiga-trust"
__author = "Infineon Technologies AG"
__author_email = "dsi-host-software@infineon.com"
__license = "MIT"
__keywords = "ECDHE ECDSA RSA ECC X509 NISTP256 NIST384 OPTIGA TRUST TRUSTX TRUSTM"
__classifiers = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: MIT License",
    "Intended Audience :: Developers",
    "Programming Language :: Python",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: POSIX :: Linux",
    "Framework :: Pytest",
]

# Parameters for setup
__packages = ["optigatrust", "optigatrust.enums", "optigatrust.rules", "optigatrust.lib"]

__package_data = {
    "optigatrust": ["*.md"],
    "optigatrust.lib": ["*.dll", "*.so", "*.ini"],
    "optigatrust.enums": ["*.xml"],
    "optigatrust.rules": ["*.rules"],
}

__package_root_dir = "src/" + __name

__package_dir = {
    "optigatrust": __package_root_dir,
}

if __name__ == "__main__":
    setup(
        name=__name,
        version=__get_version("src/optigatrust/version.py"),
        description=__desc,
        long_description=__description(),
        long_description_content_type="text/markdown",
        url=__url,
        author=__author,
        author_email=__author_email,
        keywords=__keywords,
        license=__license,
        classifiers=__classifiers,
        include_package_data=True,
        packages=__packages,
        package_dir=__package_dir,
        package_data=__package_data,
        setup_requires=["setuptools>=40", "wheel"],
        install_requires=[
            "optigatrust",
            "asn1crypto",
            "jinja2",
            "cryptography",
            "pyserial",
            "click",
        ],
        python_requires=">=3.5",
        entry_points={
            "console_scripts": [
                "optigatrust = optigatrust.clidriver:main",
            ],
        },
        cmdclass={
            "install": _install,
        },
    )
