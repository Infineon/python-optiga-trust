from setuptools import setup, find_packages
from setuptools.command.install import install

import platform
import sys
import os
import shutil


def __get_arch_os():
	platforms = {
		'linux': 'Linux',
		'linux1': 'Linux',
		'linux2': 'Linux',
		'darwin': 'OSX',
		'cygwin': 'Windows',
		'msys': 'Windows',
		'win32': 'Windows',
	}

	if sys.platform not in platforms:
		return sys.platform

	return platform.architecture()[0], platforms[sys.platform]


def __get_lib_postfix():
	targets = {
		'Linux': {
			'32bit': 'x86',
			'64bit': 'x86_64'
		},
		'Windows': {
			'32bit': 'ms32',
			'64bit': 'ms64',
		}
	}
	arch_os = __get_arch_os()

	if arch_os[1] not in targets:
		raise Exception('Platform not supported')

	return targets[arch_os[1]][arch_os[0]]


def __copy_rules(target):
	rules = 'src/optiga-trust-x/pal/libusb/include/90-optigatrust.rules'

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


def __readme():
	with open('README.md', 'r') as f:
		readme = f.read()

	return readme


class OptigaTrustInstall(install):
	def run(self):
		self.do_egg_install()
		_install_rules()


__name = 'optigatrust'
__desc = 'The ctypes Python wrapper for the Infineon OPTIGA(TM) Trust family of security solutions'
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

with open(os.path.join("lib", __name, "__init__.py")) as init_root:
	for line in init_root:
		if line.startswith("version_info"):
			version_tuple = eval(line.split("=")[1])
__version = ".".join([str(x) for x in version_tuple])

# Parameters for setup
__packages = [
	'optigatrust.pk',
	'optigatrust.rand',
	'optigatrust.util',
	'optigatrust.x509',
	'optigatrust.csrc.lib'
]

__package_data = {
	'optigatrust.csrc.lib': ['*.dll', '*.so'],
	'optigatrust.rules': [
		'csrc/optiga-trust-x/pal/libusb/include/90-optigatrust.rules'
	]
}


__package_dir = {
	"optigatrust": "lib/optigatrust",
}

if __name__ == '__main__':
	setup(
		name=__name,
		version=__version,
		description=__desc,
		long_description=__readme(),
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
		install_requires=['asn1crypto;python_version<"4"'],
		python_requires='>=3.5',
	)
