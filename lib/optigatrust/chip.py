# ============================================================================
# The MIT License
# 
# Copyright (c) 2018 Infineon Technologies AG
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
# ============================================================================
import os
import platform
import sys
from ctypes import *
import base64
import warnings
from collections import namedtuple

from optigatrust.const import x, m1, m3, m2id2, charge

__all__ = [
    'Settings',
    'Descriptor',
    'init',
    'get_info',
    'read',
    'read_meta',
    'write',
    'write_meta',
    'read_cert',
    'write_cert'
]


def _get_arch_os():
    platforms = {
        'linux': 'linux',
        'linux1': 'linux',
        'linux2': 'linux',
        'darwin': 'osx',
        'cygwin': 'win',
        'msys': 'win',
        'win32': 'win',
    }

    targets = {
        '32bit': 'i686',
        '64bit': 'amd64'
    }

    if sys.platform not in platforms:
        return sys.platform

    _, _, _, _, arch, _ = platform.uname()

    if platforms[sys.platform] == 'win':
        arch = targets[platform.architecture()[0]]

    return arch, platforms[sys.platform]


def _get_lib_name(interface='libusb'):
    arch, os = _get_arch_os()

    if os == 'win':
        extension = 'dll'
    if os == 'linux':
        extension = 'so'

    return 'liboptigatrust-{interface}-{os}-{arch}.{ext}'.format(interface=interface, os=os, arch=arch, ext=extension)


def _load_lib(interface):
    libname = _get_lib_name(interface)

    old_path = os.getcwd()

    curr_path = os.path.abspath(os.path.dirname(__file__) + "/csrc/lib/")

    os.chdir(curr_path)
    if os.path.exists(os.path.join(curr_path, libname)):
        api = cdll.LoadLibrary(os.path.join(curr_path, libname))
    else:
        api = None
        os.chdir(old_path)
        raise OSError('Unable to find library in {}. Look for {}'.format(curr_path, libname))
    api.exp_optiga_init.restype = c_int
    ret = api.exp_optiga_init()
    if ret != 0:
        os.chdir(old_path)
        raise OSError('Failed to initialise the chip. Exit.')

    os.chdir(old_path)
    return api


UID = namedtuple("UID", "cim_id platform_id model_id rommask_id chip_type batch_num x_coord y_coord fw_id fw_build")
_optiga_descriptor = None


class Settings:
    def __init__(self):
        self._current_limit = int.from_bytes(read(0xe0c4, 0), "big")
        self._sleep_activation_delay = int.from_bytes(read(0xe0c3, 0), "big")
        _uid = read(object_id=0xE0C2, force=True)
        self._uid = UID(int.from_bytes(_uid[0:1], byteorder='big'),
                        int.from_bytes(_uid[1:2], byteorder='big'),
                        int.from_bytes(_uid[2:3], byteorder='big'),
                        int.from_bytes(_uid[3:5], byteorder='big'),
                        int.from_bytes(_uid[5:11], byteorder='big'),
                        int.from_bytes(_uid[11:17], byteorder='big'),
                        int.from_bytes(_uid[17:19], byteorder='big'),
                        int.from_bytes(_uid[19:21], byteorder='big'),
                        int.from_bytes(_uid[21:25], byteorder='big'),
                        int.from_bytes(_uid[25:27], byteorder='big'))
        self._security_status = int.from_bytes(read(0xe0c1, 0), "big")
        self._global_lifecycle_state = lifecycle_states[int.from_bytes(read(0xe0c0, 0), "big")]
        self._security_event_counter = int.from_bytes(read(0xe0c5, 0), "big")

    @property
    def current_limit(self):
        return self._current_limit

    @current_limit.setter
    def current_limit(self, val: int):
        write(bytes([val]), 0xe0c4)

    @property
    def sleep_activation_delay(self):
        return self._sleep_activation_delay

    @sleep_activation_delay.setter
    def sleep_activation_delay(self, val: int):
        write(bytes([val]), 0xe0c3)

    @property
    def uid(self):
        return self._uid

    @property
    def global_lifecycle_state(self):
        return self._global_lifecycle_state

    @global_lifecycle_state.setter
    def global_lifecycle_state(self, val: str):
        if val not in lifecycle_states.values():
            raise ValueError(
                'Wrong lifecycle state. Expected {0}, your provided {1}'.format(lifecycle_states, val)
            )
        for code, state in lifecycle_states.items():
            if state == val:
                write(bytes(state), 0xe0c0)

    @property
    def security_status(self):
        return self._security_status

    @property
    def security_event_counter(self):
        self._security_event_counter = int.from_bytes(read(0xe0c5, 0), "big")
        return self._security_event_counter


class Descriptor:
    def __init__(self, api, object_id, key_id, rng, key_usage, curves):
        self._api = api
        self._object_id = object_id
        self._object_id_values = set(item.value for item in self._object_id)
        self._key_usage = key_usage
        self._key_usage_values = set(item.value for item in self._key_usage)
        self._key_id = key_id
        self._key_id_values = set(item.value for item in self._key_id)
        self._rng = rng
        self._rng_values = set(item.value for item in self._rng)
        self._curves = curves
        self._curves_values = set(item.value for item in self._curves)
        self._enabled = True
        self._settings = None

    @property
    def api(self):
        return self._api

    @property
    def object_id(self):
        return self._object_id

    @property
    def object_id_values(self):
        return self._object_id_values

    @property
    def key_usage(self):
        return self._key_usage

    @property
    def key_usage_values(self):
        return self._key_usage_values

    @property
    def key_id(self):
        return self._key_id

    @property
    def key_id_values(self):
        return self._key_id_values

    @property
    def rng(self):
        return self._rng

    @property
    def rng_values(self):
        return self._rng_values

    @property
    def curves(self):
        return self._curves

    @property
    def curves_values(self):
        return self._curves_values

    @property
    def settings(self):
        return self._settings

    @settings.setter
    def settings(self, data: Settings):
        self._settings = data


def init():
    """
    This function either initialises non-initialised communication channel between the chip and the application, or
    returns an existing communication
    ONLY ONE Optiga Instance is supported

    :param None:

    :raises:
        OSError: If some problems occured during the initialisation of the library or the chip

    :return:
        a CDLL Instance
    """
    global _optiga_descriptor

    if _optiga_descriptor is None:
        try:
            """
            Here we try to probe which interface is actually in use, might be either libusb or i2c
            We suppress stderr output of the libusb interface in case it's npot connected to not confuse
            a user
            """
            api = _load_lib('libusb')
            print('Loaded: {0}'.format(_get_lib_name('libusb')))
        except OSError:
            api = _load_lib('i2c')
            print('Loaded: {0}'.format(_get_lib_name('i2c')))

        consts = _lookup_optiga(api)
        _optiga_descriptor = Descriptor(
            api=api,
            object_id=consts.ObjectId,
            key_id=consts.KeyId,
            key_usage=consts.KeyUsage,
            rng=consts.Rng,
            curves=consts.Curves
        )
        _optiga_descriptor.settings = Settings()
        get_info()

    return _optiga_descriptor


def get_info():
    optiga = init()
    settings = optiga.settings
    print("================== OPTIGA Trust Chip Info ==================")
    print('{0:<30}{1:^10}:{2}'.format("CIM Identifier", "[bCimIdentifer]", hex(settings.uid.cim_id)))
    print('{0:<30}{1:^10}:{2}'.format("Platform Identifer", "[bPlatformIdentifier]", hex(settings.uid.platform_id)))
    print('{0:<30}{1:^10}:{2}'.format("Model Identifer", "[bModelIdentifier]", hex(settings.uid.model_id)))
    print('{0:<30}{1:^10}:{2}'.format("ID of ROM mask", "[wROMCode]", hex(settings.uid.rommask_id)))
    print('{0:<30}{1:^10}:{2}'.format("Chip Type", "[rgbChipType]", hex(settings.uid.chip_type)))
    print('{0:<30}{1:^10}:{2}'.format("Batch Number", "[rgbBatchNumber]", hex(settings.uid.batch_num)))
    print('{0:<30}{1:^10}:{2}'.format("X - coordinate", "[wChipPositionX]", hex(settings.uid.x_coord)))
    print('{0:<30}{1:^10}:{2}'.format("Y - coordinate", "[wChipPositionY]", hex(settings.uid.y_coord)))
    print('{0:<30}{1:^10}:{2}'.format("Firmware Identifier", "[dwFirmwareIdentifier]", hex(settings.uid.fw_id)))
    print('{0:<30}{1:^10}:{2}'.format("Build Number", "[rgbESWBuild]", hex(settings.uid.fw_build)))
    print('{0:<30}{1:^10}:{2}'.format("Current Limitation", "[OID: 0xE0C4]", hex(settings.current_limit)))
    print('{0:<30}{1:^10}:{2}'.format("Sleep Activation Delay", "[OID: 0xE0C3]", hex(settings.sleep_activation_delay)))
    print('{0:<30}{1:^10}:{2}'.format("Global Lifecycle State", "[OID: 0xE0C0]", settings.global_lifecycle_state))
    print('{0:<30}{1:^10}:{2}'.format("Security Status", "[OID: 0xE0C1]", hex(settings.security_status)))
    print('{0:<30}{1:^10}:{2}'.format("Security Event Counter", "[OID: 0xE0C5]", hex(settings.security_event_counter)))
    print("============================================================")


def _lookup_optiga(api):
    api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_data.restype = c_int

    d = (c_ubyte * 1700)()
    c_dlen = c_ushort(1700)

    ret = api.exp_optiga_util_read_data(c_ushort(0xE0C2), 0, d, byref(c_dlen))

    if ret == 0 and not all(_d == 0 for _d in list(bytes(d))):
        data = (c_ubyte * c_dlen.value)()
        memmove(data, d, c_dlen.value)
        _bytes = bytearray(data)
    else:
        _bytes = bytearray(0)

    _fw_build = int.from_bytes(_bytes[25:27], byteorder='big')

    if _fw_build in {0x809, 0x2440}:
        return m1
    else:
        return x


def read(object_id=0xe0e0, offset=0, force=False):
    """
    This function helps to read the data stored on the chip

    :param object_id:
        An ID of the Object (e.g. 0xe0e1)

    :param offset:
        An optional parameter defining whether you want to read the data with offset

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        bytearray with the data
    """
    optiga = init()
    api = optiga.api

    if offset > 1700:
        raise ValueError("offset should be less than the limit of 1700 bytes")

    if force is False:
        if object_id not in optiga.object_id_values:
            raise TypeError(
                "object_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.object_id),
                                                                                        object_id))

    api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_data.restype = c_int

    d = (c_ubyte * 1700)()
    c_dlen = c_ushort(1700)

    ret = api.exp_optiga_util_read_data(c_ushort(object_id), offset, d, byref(c_dlen))

    if ret == 0 and not all(_d == 0 for _d in list(bytes(d))):
        data = (c_ubyte * c_dlen.value)()
        memmove(data, d, c_dlen.value)
        _bytes = bytearray(data)
    else:
        _bytes = bytearray(0)

    return _bytes


def read_meta(data_id: int):
    """
    This function helps to read the metadata associated with the data object stored on the chip

    :param data_id:
        An ID of the Object (e.g. 0xe0e1)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        bytearray with the data
    """
    optiga = init()
    api = optiga.api

    if data_id not in optiga.object_id_values:
        raise TypeError(
            "data_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.object_id), data_id))
    elif data_id not in optiga.key_id_values:
        raise TypeError(
            "data_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.key_id), data_id))

    api.exp_optiga_util_read_metadata.argtypes = c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_metadata.restype = c_int

    d = (c_ubyte * 100)()
    c_dlen = c_ushort(100)

    ret = api.exp_optiga_util_read_metadata(c_ushort(data_id), d, byref(c_dlen))

    if ret == 0 and not all(_d == 0 for _d in list(bytes(d))):
        data = (c_ubyte * c_dlen.value)()
        memmove(data, d, c_dlen.value)
        _bytes = bytearray(data)
    else:
        _bytes = bytearray(0)

    return _bytes


def write_meta(data, data_id: int):
    """
    This function helps to write the metadata associated with the data object stored on the chip

    :param data:
        Data to write, should be bytearray

    :param data_id:
        An ID of the Object (e.g. 0xe0e1)

    :raises
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
    """
    optiga = init()
    api = optiga.api

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        raise TypeError("data should be bytes type")

    if data_id not in optiga.object_id_values:
        raise TypeError(
            "data_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.object_id), data_id))
    elif data_id not in optiga.key_id_values:
        raise TypeError(
            "data_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.key_id), data_id))

    _data = (c_ubyte * len(data))(*data)

    api.exp_optiga_util_write_metadata.argtypes = c_ushort, POINTER(c_ubyte), c_ubyte
    api.exp_optiga_util_write_metadata.restype = c_int

    ret = api.exp_optiga_util_write_metadata(c_ushort(data_id), _data, len(_data))

    if ret != 0:
        raise ValueError(
            'Some problems during communication. You have possible selected one of locked objects'
        )


def write(data, object_id: int, offset=0):
    """
    This function helps to write the data stored on the chip

    :param data:
        Data to write, should be either bytes of bytearray

    :param object_id:
        An ID of the Object (e.g. 0xe0e1)

    :param offset:
        An optional parameter defining whether you want to read the data with offset

    :raises
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
    """
    optiga = init()
    api = optiga.api

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        raise TypeError("data should be bytes type")

    if object_id not in optiga.object_id_values:
        raise TypeError(
            "object_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.object_id), object_id))

    if len(data) > 1700:
        raise ValueError("length of data exceeds the limit of 1700")

    if offset > 1700:
        raise ValueError("offset should be less than the limit of 1700 bytes")

    api.exp_optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
    api.exp_optiga_util_write_data.restype = c_int

    _data = (c_ubyte * len(data))(*data)

    ret = api.exp_optiga_util_write_data(c_ushort(object_id), 0x40, offset, _data, len(data))

    if ret != 0:
        raise ValueError(
            'Some problems during communication. You have possible selected one of locked objects'
        )


def _break_apart(f, sep, step):
    return sep.join(f[n:n + step] for n in range(0, len(f), step))


def read_cert(cert_id=0xe0e0, to_pem=False):
    """
    This function returns an exisiting certificate from the OPTIGA(TM) Trust device

    :param cert_id:
        An ID of the Object (e.g. 0xe0e1)

    :param to_pem:
        A boolean flag to indecate, whether you want return certificate PEM encoded

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        A byte string with a PEM certificate or DER encoded byte string
    """
    optiga = init()

    oid = optiga.object_id

    if cert_id not in optiga.object_id_values:
        raise TypeError(
            'Certificate Slot is not correct. '
            'Supported values are in ObjectId class you used {0}'.format(cert_id)
        )
    if cert_id not in {oid.IFX_CERT.value, oid.USER_CERT_1.value, oid.USER_CERT_2.value, oid.USER_CERT_3.value,
                       oid.TRUST_ANCHOR_1.value, oid.TRUST_ANCHOR_2.value,
                       oid.DATA_SLOT_1500B_0, oid.DATA_SLOT_1500B_1}:
        warnings.warn("You are going to use an object which is outside of the standard certificate storage")

    der_cert = read(cert_id)

    # print(list(der_cert))

    if len(der_cert) == 0:
        raise ValueError(
            'Certificate Slot {0} is empty'.format(cert_id)
        )

    # OPTIGA Trust Code to tag an X509 certificate
    if der_cert[0] == 0xC0:
        der_cert = der_cert[9:]

    if to_pem:
        pem_cert = "-----BEGIN CERTIFICATE-----\n"
        pem_cert += _break_apart(base64.b64encode(der_cert).decode(), '\n', 64)
        pem_cert += "\n-----END CERTIFICATE-----"
        return pem_cert.encode()
    else:
        return bytes(der_cert)


def _append_length(data, last=False):
    data_with_length = bytearray(3)
    left = len(data)

    data_with_length[2] = left % 0x100

    left = left >> 8
    data_with_length[1] = left % 0x100

    if last:
        data_with_length[0] = 0xC0
    else:
        left = left >> 8
        data_with_length[0] = left % 0x100

    data_with_length.extend(data)

    return data_with_length


def _strip_cert(cert):
    if cert.split('\n')[0] != "-----BEGIN CERTIFICATE-----":
        raise ValueError(
            'Incorrect Certificate '
            'Should start with "-----BEGIN CERTIFICATE-----" your starts with {0}'.format(cert.split('\n')[0])
        )
    raw_cert = cert.replace('-----BEGIN CERTIFICATE-----', '')
    raw_cert = raw_cert.replace('-----END CERTIFICATE-----', '')
    raw_cert = raw_cert.replace("\n", "")
    der_cert = base64.b64decode(raw_cert)

    return der_cert


def write_cert(cert, cert_id=0xe0e1):
    """
    This function writes a new certificate into the OPTIGA(TM) Trust device

    :param cert:
        Should be a a string with a PEM file with newlines separated or a bytes insatnce with DER encoded cert

    :param cert_id:
        An ID of the Object (e.g. 0xe0e1)

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        None
    """
    optiga = init()
    api = optiga.api
    oid = optiga.object_id

    if cert_id not in {oid.IFX_CERT.value, oid.USER_CERT_1.value, oid.USER_CERT_2.value, oid.USER_CERT_3.value,
                       oid.TRUST_ANCHOR_1.value, oid.TRUST_ANCHOR_2.value,
                       oid.DATA_SLOT_1500B_0, oid.DATA_SLOT_1500B_1}:
        warnings.warn("You are going to use an object which is outside of the standard certificate storage")

    if not isinstance(cert, str) and not isinstance(cert, bytes) and not isinstance(cert, bytearray):
        raise TypeError(
            'Bad certificate type should be either bytes, bytes string, or string'
        )

    # Looks like a DER encoded files has been provided
    if isinstance(cert, bytes) or isinstance(cert, bytearray):
        try:
            cert = cert.decode("utf-8")
            cert = _strip_cert(cert)
        except UnicodeError:
            pass
    elif isinstance(cert, str):
        cert = _strip_cert(cert)
    else:
        raise TypeError(
            'Bad certificate type should be either bytes, bytes string, or string'
        )

    der_cert = cert

    if der_cert[0] != 0x30:
        raise ValueError(
            'Incorrect Certificate '
            'Should start with 0x30 your starts with {0}'.format(der_cert[0])
        )

    # Append tags
    # [len_byte_2, len_byte_1, len_byte_0] including the certificate and two lengths
    #   [len_byte_2, len_byte_1, len_byte_0] including the certificate and the length
    #       [len_byte_2, len_byte_1, len_byte_0]
    #           [der_encoded_certificate]
    # Write the result into the given Object ID
    l1_der_cert = _append_length(der_cert)
    l2_der_cert = _append_length(l1_der_cert)
    l3_der_cert = _append_length(l2_der_cert, last=True)

    # print("Certificate without encoding #1 {0}".format(list(der_cert)))
    # print("Certificate without encoding #2 {0}".format(list(l1_der_cert)))
    # print("Certificate without encoding #3 {0}".format(list(l2_der_cert)))
    # print("Certificate without encoding #4 {0}".format(list(l3_der_cert)))

    write(l3_der_cert, cert_id)


lifecycle_states = {
    0x01: 'creation',
    0x03: 'initialisation',
    0x05: 'operational',
    0x07: 'termination'
}
