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
from collections import namedtuple
import warnings

from optigatrust.const import x, m1, m3, m2id2, charge

__all__ = [
    'Settings',
    'Descriptor',
    'Object',
    'init',
    'random',
    'get_info',
    'lifecycle_states',
    'parse_raw_meta',
    'prepare_raw_meta',
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
        self._current_limit = int.from_bytes(Object(0xe0c4).read(), "big")
        self._sleep_activation_delay = int.from_bytes(Object(0xe0c3).read(), "big")
        _uid = Object(0xe0c2).read(force=True)
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
        self._security_status = int.from_bytes(Object(0xe0c1).read(), "big")
        self._global_lifecycle_state = lifecycle_states[int.from_bytes(Object(0xe0c0).read(), 'big')]
        self._security_event_counter = int.from_bytes(Object(0xe0c5).read(), "big")

    @property
    def current_limit(self):
        return self._current_limit

    @current_limit.setter
    def current_limit(self, val: int):
        Object(0xe0c4).write(bytes([val]))

    @property
    def sleep_activation_delay(self):
        return self._sleep_activation_delay

    @sleep_activation_delay.setter
    def sleep_activation_delay(self, val: int):
        Object(0xe0c3).write(bytes([val]))

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
                Object(0xe0c0).write(bytes(state))

    @property
    def security_status(self):
        return self._security_status

    @property
    def security_event_counter(self):
        self._security_event_counter = int.from_bytes(Object(0xe0c5).read(), "big")
        return self._security_event_counter


class Descriptor:
    def __init__(self, api, name, object_id, key_id, session_id, rng, key_usage, curves):
        self.api = api
        self.name = name
        self.object_id = object_id
        self.object_id_values = set(item.value for item in self.object_id)
        self.key_usage = key_usage
        self.key_usage_values = set(item.value for item in self.key_usage)
        self.key_id = key_id
        self.key_id_values = set(item.value for item in self.key_id)
        self.session_id = session_id
        self.session_id_values = set(item.value for item in self.session_id)
        self.rng = rng
        self.rng_values = set(item.value for item in self.rng)
        self.curves = curves
        self.curves_values = set(item.value for item in self.curves)
        self.enabled = True
        self._settings = None

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

    :returns:
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

        consts, name = _lookup_optiga(api)
        _optiga_descriptor = Descriptor(
            api=api,
            name=name,
            object_id=consts.ObjectId,
            key_id=consts.KeyId,
            session_id=consts.SessionId,
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

    if _fw_build in {0x809}:
        return m1, "OPTIGA™ Trust M V1 (SLS32AIA010MH/S)"
    if _fw_build in {0x2440}:
        return m3, "OPTIGA™ Trust M V3 (SLS32AIA010ML/K)"
    else:
        return x, "OPTIGA™ Trust X (SLS32AIA020X2/4)"


def random(n, trng=True):
    """
    This function generates a random number

    :param n:
        how much randomness to generate. Valid values are from 8 to 256

    :param trng:
        If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        Bytes object with randomness
    """
    optiga = init()
    api = optiga.api

    api.exp_optiga_crypt_random.argtypes = c_byte, POINTER(c_ubyte), c_ushort
    api.exp_optiga_crypt_random.restype = c_int
    p = (c_ubyte * n)()

    if trng is True:
        ret = api.exp_optiga_crypt_random(optiga.rng.TRNG.value, p, len(p))
    else:
        ret = api.exp_optiga_crypt_random(optiga.rng.DRNG.value, p, len(p))

    if ret == 0:
        return bytes(p)
    else:
        return bytes(0)


lifecycle_states = {
    0x01: 'creation',
    0x03: 'initalisation',
    0x07: 'operational',
    0x0f: 'termination'
}

_lifecycle_states_swaped = {y: x for x, y in lifecycle_states.items()}

_key_usages = {
    'authentication': 0x01,
    'encryption': 0x02,
    'signature': 0x10,
    'key_agreement': 0x20,
}

_key_usages_swaped = {y: x for x, y in _key_usages.items()}

_meta_tags = {
    'execute': 0xd3,
    'change': 0xd0,
    'read': 0xd1,
    'metadata': 0x20,
    'lcso': 0xc0,
    'version': 0xc1,
    'max_size': 0xc4,
    'used_size': 0xc5,
    'algorithm': 0xe0,
    'key_usage': 0xe1,
    'type': 0xe8,
    'reset_type': 0xf0,
}

_meta_tags_swaped = {y: x for x, y in _meta_tags.items()}

_algorithms = {
    'secp256r1': 0x03,
    'secp384r1': 0x04,
    'secp521r1': 0x05,
    'brainpoolp256r1': 0x13,
    'brainpoolp384r1': 0x15,
    'brainpoolp512r1': 0x16,
    'rsa1024': 0x41,
    'rsa2048': 0x42,
    'aes128': 0x81,
    'aes192': 0x82,
    'aes256': 0x83,
    'sha256': 0xe2
}

_algorithms_swaped = {y: x for x, y in _algorithms.items()}

_access_conditions_ids = {
    'always': 0x00,
    # 2 bytes, e.g. Enable access if boot phase flag in Security Status application is set → 0x10, 0x20
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_g': 0x10,
    # 3 bytes, for instance data object read is allowed only under shielded connection using a pre shared secret
    # 1) Read, Conf, Binding Secret (e.g. 0xD1, 0x03, 0x20, 0xE1, 0x40) In case of reading a data object (e.g. using
    # GetDataObject), the shielded connection must be established already using the specified Binding secret (e.g.
    # 0xE140) and the response is requested with protection (encrypted).
    # 2) Change, Conf, Binding Secret (e.g. 0xD0,
    # 0x03, 0x20, 0xE1, 0x40) In case of writing a data object (e.g. using SetDataObject), the shielded connection
    # must be established already using the specified pre-shared secret (0xE140) and the command is sent with
    # protection (encrypted).
    # 3) Execute, Conf, Binding Secret (e.g. 0xD3, 0x03, 0x20, 0xE1, 0x40) In case of using a
    # data object with an internal operation (e.g. using DeriveKey from a pre-shared secret), the shielded connection
    # must be established already using the specified binding secret (0xE140) and the command is sent protection (
    # encrypted).
    # 4) Change, Conf, Protected Update Secret → (e.g. 0xD0, 0x03, 0x20, 0xF1, 0xD0) In case of writing a
    # data object (using SetObjectProtected), the manifest must specify the same Protected Update Secret (e.g. 0xF1,
    # 0xD0) which is specified in the object metadata. This enforces to use the defined Protected Update Secret to
    # decrypt the object data in fragments.
    # Notes: Conf (Protected Update Secret) must be used in association(
    # Operator AND) with Integrity (Trust Anchor), to enforce the right Protected Update Secret to be used to decrypt
    # the object data as part of SetObjectProtected. If Conf (Protected Update Secret) not specified in the metadata
    # access conditions, SetObjectProtected uses Protected Update Secret specified in the manifest, to decrypt the
    # object data as part of fragments. The usage of this identifier is to enforce the right secret used (Integrity
    # Trust Anchor, Operator AND, Confidentiality Protected Update Secret OID). The Protected Update Secret must not
    # same as the target data object to be updated.
    'conf': 0x20,
    # 3 byte; Value, Key Reference
    # (e.g. Int first Session Key → 0x21, 0xF1, 0xF0)
    # 1) Read, Int, Binding Secret (e.g. 0xD1, 0x03, 0x21, 0xE1, 0x40)
    # In case of reading a data object (e.g. using GetDataObject), the shielded connection must be established already
    # using the specified pre-shared secret (0xE140) and the response is requested with protection (MAC).
    # 2) Change, Int, Binding Secret (e.g. 0xD0, 0x03, 0x21, 0xE1, 0x40)
    # In case of writing a data object (e.g. using SetDataObject), the shielded connection must be established already
    # using the specified pre-shared secret (0xE140) and the command is sent with protection (MAC).
    # 3) Execute, Int, Binding Secret (e.g. 0xD3, 0x03, 0x21, 0xE1, 0x40)
    # In case of using a data object with an internal operation (e.g. using DeriveKey from a pre-shared secret), the
    # shielded connection must be established already using the specified pre-shared secret (0xE140) and the command
    # is sent with protection (MAC).
    # 4) Change, Int, Trust Anchor (e.g. 0xD0, 0x03, 0x21, 0xE0, 0xEF)
    # In case of writing a data object (e.g. using SetObjectProtected), the signature associated with the meta data
    # in the manifest must be verified with the addressed trust anchor (e.g. 0xE0EF) in the access conditions. In case
    # of SetObjectProtected command, the change access conditions of target OID must have Integrity access condition
    # identifier with the respective Trust Anchor.
    'int': 0x21,
    # 3 byte; Value, Reference (Authorization Reference OID)
    # (e.g. Auto → 0x23, 0xF1, 0xD0)
    'auto': 0x23,
    # 3 byte; Value, Counter Reference
    # (e.g. Linked Counter 1 → 0x40, 0xE1, 0x20)
    # For example, The arbitrary data object holds a pre-shared secret and this secret is allowed to be used for
    # key derivation
    # (DeriveKey) operations to a limited number of times. To enable this, choose a counter object
    # (updated with maximum allowed limit) and assign the counter data object in the EXE access condition of arbitrary
    # data object as shown below.
    # (e.g. EXE, Luc, Counter Object → 0xD3, 0x03, 0x40, 0xE1, 0x20)
    # The counter data objects gets updated (counter value gets incremented by 1 up to maximum limit)
    # automatically when the DeriveKey command is performed.
    'luc': 0x40,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsG < op → 0x70, 0xFC, 0x07)
    'lcsg': 0x70,
    # 2 byte; Value
    # (e.g. Enable access if boot phase flag in Security Status application is set → 0x90, 0x20)
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_a': 0x90,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsA > in → 0xE0, 0xFB, 0x03)
    'lcsa': 0xe0,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsO < op → 0xE1, 0xFC, 0x07)
    'lcso': 0xe1,
    '==': 0xfa,
    '>': 0xfb,
    '<': 0xfc,
    '&&': 0xfd,
    '||': 0xfe,
    'never': 0xff
}

_access_conditions_ids_swaped = {y: x for x, y in _access_conditions_ids.items()}

_data_object_types = {
    # SRM: BSTR. The Byte String data object type is represented by a sequence of bytes, which could be addressed by
    # offset and length.
    'byte_string': 0x00,
    # SRM: UPCTR. The Up-counter data type implements a counter with a current value which could be increased only
    # and a threshold terminating the counter.
    'up_counter': 0x01,
    # SRM: TA. The Trust Anchor data type contains a single X.509 certificate which could be used in various commands
    # requiring a root of trust.
    'trust_anchor': 0x11,
    # SRM: DEVCERT. The Device Identity data type contains a single X.509 certificate or a chain of certificates
    # (TLS, USB-Type C, ...) which was issued to vouch for the cryptographic identity of the end-device.
    'device_cert': 0x12,
    # SRM: PRESSEC. The Pre-shared Secret contains a binary data string which makes up a pre-shared secret for various
    # purposes (FW-decryption, ...).
    'pre_sh_secret': 0x21,
    # SRM: PTFBIND. The Platform Binding contains a binary data string which makes up a pre-shared secret for platform
    # binding (e.g. used for OPTIGA™ Shielded Connection).
    'platform_binding': 0x22,
    # SRM: UPDATESEC. The Protected Update Secret contains a binary data string which makes up a pre-shared secret for
    # confidentiality protected update of data or key objects. The maximum length is limited to 64 bytes, even if the
    # hosting data object has a higher maximum length.
    'update_secret': 0x23,
    # SRM: AUTOREF. The Authorization Reference contains a binary data string which makes up a reference value for
    # verifying an external entity (admin, user, etc.) authorization.
    'authorization_ref': 0x31
}

_data_object_types_swaped = {y: x for x, y in _data_object_types.items()}


def parse_raw_meta(meta: bytes):
    """
    This function should process the given metadata and return it in a human readable form.

    :param meta:
        metadata represented in bytes

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        A dictionary of the following format::

            {
                'read': 'always'
                'execute': ['lcso', '<', 'operational']
            }

    """
    global _access_conditions_ids_swaped
    global _meta_tags_swaped
    if not isinstance(meta, bytes) and not isinstance(meta, bytearray):
        raise TypeError(
            'Metadata (meta) should be in bytes form, you provided {0}'.format(type(meta))
        )
    meta_tuple = tuple(meta)
    meta_itr = iter(meta_tuple)
    # First byte is always 20
    # For instance
    # [ 20,
    #   17,
    #   c0, 01, 01,
    #   c4, 02, 06, c0,
    #   c5, 02, 01, e5',
    #   d0, 01, ff,
    #   d1, 01, 00,
    #   d3, 01, 00,
    #   e8, 01, 12 ]
    # We skip the very first tag, then record the length o the meta data, then go tag by tag (line by line here).
    # Some tags, like lcso or algorithm have a different value which should be interepeted differently
    next(meta_itr)
    meta_size = next(meta_itr)
    if meta_size == 0:
        return None
    if meta_size < 0:
        raise ValueError(
            'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
        )
    # 64 for is the maximum
    if meta_size > 62:
        raise ValueError(
            'Metadata Size can\'t be more than 64 bytes. You have {0}'.format(meta_size)
        )
    meta_parsed = dict()
    try:
        while True:
            tag = _meta_tags_swaped[next(meta_itr)]
            tag_size = next(meta_itr)
            if tag_size == 0:
                return None
            if tag_size < 0:
                raise ValueError(
                    'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
                )
            if tag == 'used_size' or tag == 'max_size':
                if tag_size == 2:
                    meta_parsed[tag] = (next(meta_itr) << 8) + next(meta_itr)
                elif tag_size == 1:
                    meta_parsed[tag] = next(meta_itr)
                else:
                    raise ValueError(
                        'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
                    )
                continue
            if tag == 'type':
                meta_parsed[tag] = _data_object_types_swaped[next(meta_itr)]
                continue
            if tag == 'algorithm':
                meta_parsed[tag] = _algorithms_swaped[next(meta_itr)]
                continue
            if tag == 'key_usage':
                key_usage_bytes = next(meta_itr)
                tag_data = list()
                if key_usage_bytes & _key_usages['authentication']:
                    tag_data.append('authentication')
                if key_usage_bytes & _key_usages['encryption']:
                    tag_data.append('encryption')
                if key_usage_bytes & _key_usages['signature']:
                    tag_data.append('signature')
                if key_usage_bytes & _key_usages['key_agreement']:
                    tag_data.append('key_agreement')
                meta_parsed[tag] = tag_data
                continue
            tag_data = list()
            i = 0
            while i < tag_size:
                _id = next(meta_itr)
                i += 1
                if _id in _access_conditions_ids_swaped:
                    # Conf, Int, auto and luc have as the last two bytes a reference to the oid used for the expression
                    # it is just another OID from the system
                    if _id == _access_conditions_ids['conf'] \
                            or _id == _access_conditions_ids['int'] \
                            or _id == _access_conditions_ids['auto'] \
                            or _id == _access_conditions_ids['luc']:
                        tag_data.append(_access_conditions_ids_swaped[_id])
                        tag_data.append(hex(next(meta_itr)))
                        tag_data.append(hex(next(meta_itr)))
                        i += 2
                    elif _id == _access_conditions_ids['sec_sta_a'] \
                            or _id == _access_conditions_ids['sec_sta_g']:
                        tag_data.append(_access_conditions_ids_swaped[_id])
                        tag_data.append(hex(next(meta_itr)))
                        i += 1
                    else:
                        tag_data.append(_access_conditions_ids_swaped[_id])
                # if we didn't meet the number, it should be in the lifecycle states
                elif _id in lifecycle_states:
                    tag_data.append(lifecycle_states[_id])
                else:
                    tag_data.append(hex(_id))
            if tag_size == 1:
                tag_data = ''.join(tag_data)
            meta_parsed[tag] = tag_data
    except StopIteration:
        return meta_parsed


def _prepare_access_conditions(key, value: list) -> list:
    meta = list()
    size = 0
    meta.append(_meta_tags[key])
    # as this is a list, we can find out how many bytes is required in advance
    meta.append(len(value))
    # we would like to skip some of values
    value_iter = iter(value)
    for element in value_iter:
        if element == 'int' or element == 'conf' or element == 'auto' or element == 'luc':
            _meta = [
                _access_conditions_ids[element],
                int(next(value_iter), 16),
                int(next(value_iter), 16),
            ]
        elif element == 'sec_sta_g' or element == 'sec_sta_a':
            _meta = [
                _access_conditions_ids[element],
                int(next(value_iter), 16)
            ]
        elif element in _lifecycle_states_swaped:
            _meta = [_lifecycle_states_swaped[element]]
        elif element not in _access_conditions_ids:
            raise ValueError(
                'Value for Access Condition isn\'t found. '
                'Accepted values {0}, you provided {1}'.format(_access_conditions_ids.keys(), element)
            )
        else:
            _meta = [_access_conditions_ids[element]]
        meta += _meta
        # Update the size (1 comes from the length done at the beggining )
        size += len(_meta)

    return meta


def _prepare_key_usage(key, value) -> int and list:
    key_usage = 0
    # the value should be of type list()
    if not isinstance(value, list):
        raise TypeError(
            'key usage tag should be provided in the form of a list for instance [\'x\', \'y\', \'z\']'
        )
    for i in value:
        if i not in _key_usages:
            raise ValueError(
                'key usage isn\'t supported. Supported values {0}, you provided {1}'.format(_key_usages, i)
            )
        key_usage |= _key_usages[i]

    meta = [
        _meta_tags[key],  # key
        1,                # size
        key_usage         # value
    ]

    return meta


def _prepare_algorithm(key, value) -> list:
    if value not in _algorithms:
        raise ValueError(
            'Value for Algorithm meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_algorithms.keys(), value)
        )
    meta = [
        _meta_tags[key],    # key
        1,                  # size
        _algorithms[value]  # value
    ]

    return meta


def _prepare_type(key, value) -> list:
    if value not in _data_object_types:
        raise ValueError(
            'Value for Type meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_data_object_types.keys(), value)
        )
    meta = [
        _meta_tags[key],           # key
        1,                         # size
        _data_object_types[value]  # value
    ]

    return meta


def _prepare_meta_and_size(key, value) -> list:
    # This is how the result should look like
    # key  size  value
    # Used size and max size tags can't be send to the chip, so ignore them with a warning
    if key == 'used_size' or key == 'max_size':
        warnings.warn('The used size tag and max size tag cannot be defined by a user.Skip.')
        return list()
    # Parse each key, and construct a
    elif key == 'type':
        meta = _prepare_type(key, value)
    elif key == 'algorithm':
        meta = _prepare_algorithm(key, value)
    elif key == 'key_usage':
        meta = _prepare_key_usage(key, value)
    # otherwise the value is most likely an access condition expression
    elif isinstance(value, list):
        meta = _prepare_access_conditions(key, value)
    else:
        if value not in _access_conditions_ids:
            raise ValueError(
                'Tag {0} isn\'t supported'.format(value)
            )
        # typical for 'always', 'never'
        meta = [
            _meta_tags[key],               # key
            1,                             # size
            _access_conditions_ids[value]  # value
        ]
    return meta


def prepare_raw_meta(new_meta: dict):
    """
    This function takes as an imput json-like formatted dictionary and translates it to the data to write into the chip

    :param new_meta:
        A dictionary (json like formatted) with new metadata; e.g.::

            {
                "lcso": "creation",
                "change": [
                    "lcso",
                    "<",
                    "operational"
                ],
                "execute": "always",
                "algorithm": "nistp384r1",
                "key_usage": "21"
            }

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library
    :returns:
        a bytearray with resulting metadata to write into the chip
    """
    meta = list()
    # This is how the result should look like
    # Global tag   size  key[0]  size[0]  value[0]  key[1]  size[1]  value[1]  key[2]  size[2]  value[2]
    # 20           09    C0      01       03        C4      01       8C        C5      01       0A
    meta.append(0x20)
    # first global size, we will update it later on with new keys, sizes and values appended
    meta.append(0)
    # We get as an input a dictionary, which is handy, we go entry by entry and add them correspondingly in the meta
    for key, value in new_meta.items():
        if key not in _meta_tags:
            raise ValueError(
                'Wrong value. Accepted values: {0}, you provided {1}'.format(_meta_tags.keys(), key)
            )
        # here we call a global parser for all known keys, as a result we should get a sequence of bytes which will have
        # key[n], size[n], value[n] prepared based on the given key entry (n)
        _meta = _prepare_meta_and_size(key, value)
        meta += _meta
        # Update the size of the metadata based on the returned value
        meta[1] += len(_meta)
    print(meta)
    return bytearray(meta)


class Object:
    """
    A class used to represent an Object on the OPTIGA Trust Chip

    :ivar id: the id of the object; e.g. 0xe0e0
    :vartype id: int

    :ivar optiga: the instance of the OPTIGA handler used internally by the Object class
    :vartype optiga: core.Descriptor

    :ivar updated: This boolean variable notifies whether metadata or data has been updated and this can bu used to
    notify other modules to reread data if needed
    :vartype updated: bool
    """

    def __init__(self, _id):
        """
        This class

        :param _id:
            an Object ID which you would like to initialise; e.g. 0xe0e0

        return:
            self
        """
        self.id = _id
        self.optiga = init()
        # A flag to understand whether the object was recently updated
        self.updated = False

    @property
    def meta(self):
        """ A dictionary of the metadata present right now on the chip for the given object. It is writable,
        so user can update the metadata assigning the value to it
        """
        _array_meta = self.read_raw_meta()
        return parse_raw_meta(_array_meta)

    @meta.setter
    def meta(self, new_meta: dict):
        meta = prepare_raw_meta(new_meta)
        self.write_raw_meta(meta)

    def read(self, offset=0, force=False):
        """
        This function helps to read the data stored on the chip

        :param offset:
            An optional parameter defining whether you want to read the data with offset

        :param force:
            This is a parameter which can be used to try to read the data even if id can't be somehow finden

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :return:
            bytearray with the data
        """
        api = self.optiga.api

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        if force is False:
            if self.id not in self.optiga.object_id_values:
                raise TypeError(
                    "object_id not found. \n\r Supported = {0},\n\r  "
                    "Provided = {1}".format(list(hex(self.optiga.object_id)), self.id))

        api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
        api.exp_optiga_util_read_data.restype = c_int

        d = (c_ubyte * 1700)()
        c_dlen = c_ushort(1700)

        ret = api.exp_optiga_util_read_data(c_ushort(self.id), offset, d, byref(c_dlen))

        if ret == 0:
            data = (c_ubyte * c_dlen.value)()
            memmove(data, d, c_dlen.value)
            _bytes = bytearray(data)
        else:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        return _bytes

    def write(self, data, offset=0):
        """
        This function helps to write the data onto the chip

        :param data:
            Data to write, should be either bytes of bytearray

        :param offset:
            An optional parameter defining whether you want to read the data with offset

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if self.id not in self.optiga.object_id_values:
            raise TypeError(
                "object_id not found. \n\r Supported = {0},\n\r  "
                "Provided = {1}".format(list(hex(self.optiga.object_id)), self.id))

        if len(data) > 1700:
            raise ValueError("length of data exceeds the limit of 1700")

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        api.exp_optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
        api.exp_optiga_util_write_data.restype = c_int

        _data = (c_ubyte * len(data))(*data)

        ret = api.exp_optiga_util_write_data(c_ushort(self.id), 0x40, offset, _data, len(data))

        if ret != 0:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        self.updated = True

    def read_raw_meta(self) -> bytearray:
        """
        This function helps to read the metadata associated with the data object stored on the chip

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :returns:
            bytearray with the data
        """
        api = self.optiga.api

        if (self.id not in self.optiga.object_id_values) and (self.id not in self.optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga.object_id)),
                    list(hex(self.optiga.key_id)),
                    self.id)
            )

        api.exp_optiga_util_read_metadata.argtypes = c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
        api.exp_optiga_util_read_metadata.restype = c_int

        d = (c_ubyte * 100)()
        c_dlen = c_ushort(100)

        ret = api.exp_optiga_util_read_metadata(c_ushort(self.id), d, byref(c_dlen))

        if ret == 0:
            data = (c_ubyte * c_dlen.value)()
            memmove(data, d, c_dlen.value)
            _bytes = bytearray(data)
        else:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        return _bytes

    def write_raw_meta(self, data):
        """
        This function helps to write the metadata associated with the data object stored on the chip

        :param data:
            Data to write, should be bytearray

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if (self.id not in self.optiga.object_id_values) and (self.id not in self.optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga.object_id)),
                    list(hex(self.optiga.key_id)),
                    self.id)
            )

        _data = (c_ubyte * len(data))(*data)

        api.exp_optiga_util_write_metadata.argtypes = c_ushort, POINTER(c_ubyte), c_ubyte
        api.exp_optiga_util_write_metadata.restype = c_int

        ret = api.exp_optiga_util_write_metadata(c_ushort(self.id), _data, len(_data))

        if ret != 0:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        self.updated = True
