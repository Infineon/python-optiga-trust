# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

from setuptools import setup, find_packages
from setuptools.command.install import install

import platform
import sys
import os
import shutil


def __copy_rules(target):
    rules = 'rules/90-optigatrust.rules'

    if not os.path.exists(target):
        raise FileNotFoundError

    if not os.path.exists(target + os.path.sep + os.path.basename(rules)):
        shutil.copy(rules, target)


def _install_rules():
    if sys.platform.startswith('linux'):
        try:
            __copy_rules('/etc/udev/rules.d')
        except PermissionError:
            print('Install udev rules failed, install as sudo or manually')
        except:
            print('Install udev rules failed')


def __description():
    description_file = os.path.join("src" , "optigatrust", "DESCRIPTION.md")
    with open(description_file, 'r', encoding='utf-8') as f:
        readme = f.read()

    return readme


class OptigaTrustInstall(install):
    def run(self):
        self.do_egg_install()
        _install_rules()


__name = 'optigatrust'
__desc = 'A ctypes based Python wrapper for the OPTIGA™ Trust M Host Library for C'
__url = 'https://github.com/infineon/python-optiga-trust'
__author = 'Infineon Technologies AG'
__author_email = 'DSSTechnicalSupport@infineon.com'
__license = 'MIT'
__keywords = 'ECDHE ECDSA RSA ECC X509 NISTP256 NIST384 OPTIGA TRUST TRUSTX TRUSTM'
__classifiers = [
    'Development Status :: 4 - Beta',
    'License :: OSI Approved :: MIT License',
    'Intended Audience :: Developers',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3.7',
    'Operating System :: Microsoft :: Windows',
    'Operating System :: Microsoft :: Windows :: Windows 8',
    'Operating System :: Microsoft :: Windows :: Windows 8.1',
    'Operating System :: Microsoft :: Windows :: Windows 10',
    'Operating System :: POSIX :: Linux'
]

# Parameters for setup
__packages = [
    'optigatrust',
    'optigatrust.enums',
    'optigatrust.rules',
    'optigatrust.lib'
]

__package_data = {
    'optigatrust': ['*.md'],
    'optigatrust.lib': ['*.dll', '*.so', '*.ini'],
    'optigatrust.enums': ['*.xml'],
    'optigatrust.rules': ['*.rules']
}

__package_root_dir = "src/" + __name

__package_dir = {
    "optigatrust": __package_root_dir,
}

with open(os.path.join(__package_root_dir, "version.py")) as init_root:
    for line in init_root:
        if line.startswith("__version_info__"):
            __version_tuple__ = eval(line.split("=")[1])
    __version = ".".join([str(x) for x in __version_tuple__])

if __name__ == '__main__':
    setup(
        name=__name,
        version=__version,
        description=__desc,
        long_description=__description(),
        long_description_content_type='text/markdown',
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
        setup_requires=['setuptools>=40', 'wheel'],
        install_requires=['optigatrust', 'asn1crypto', 'jinja2', 'cryptography', 'pyserial', 'click'],
        python_requires='>=3.5',
        entry_points={
            'console_scripts': [
                'optigatrust = optigatrust.clidriver:main',
            ],
        },
    )
