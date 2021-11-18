#!/usr/bin/env python
"""This module defines chip and object related base classes of the optigatrust package """
# pylint: disable=too-many-lines
# for the time-being this file is large, a major restructure is required

from collections import namedtuple
import warnings

from .version import __version__, __version_info__
from . import _backend


__all__ = [
    '__version__',
    '__version_info__',
    'enums',
    'objects',
    'crypto',
    'csr',
    'port',
    'lifecycle_states',
    'Chip',
    'Object'
]


UID = namedtuple("UID", "cim_id platform_id model_id rommask_id chip_type batch_num x_coord y_coord fw_id fw_build")


# pylint: disable=too-many-instance-attributes disable=no-self-use
# 14 is a reasonable amount as it represents a real amount of properties.
# Parameters are related to the chip and don't use self, but shouldn't be distinct functions
class Chip:
    """
    A class used to represent the whole OPTIGA Trust Chip
    """
    def __init__(self):
        """
        This class

        This function either initialises non-initialised communication channel between the chip and the application, or
        returns an existing communication
        ONLY ONE Optiga Instance is supported

        :ivar opts: you can provide here a COMPort number (for Windows); e.g. COM21 to which an EvalKit is connected

        :raises:
            OSError: If some problems occured during the initialisation of the library or the chip

        return:
            self
        """

        optiga_cddl = _backend.get_handler()

        self.api = optiga_cddl
        consts, name = _backend.lookup_optiga(optiga_cddl)
        self._name = name
        self.object_id = consts.ObjectId
        self.object_id_values = set(item.value for item in self.object_id)
        self.key_usage = consts.KeyUsage
        self.key_usage_values = set(item.value for item in self.key_usage)
        self.key_id = consts.KeyId
        self.key_id_values = set(item.value for item in self.key_id)
        self.session_id = consts.SessionId
        self.session_id_values = set(item.value for item in self.session_id)
        self.rng = consts.Rng
        self.rng_values = set(item.value for item in self.rng)
        self.curves = consts.Curves
        self.curves_values = set(item.value for item in self.curves)

    @property
    def name(self):
        """
        This property returns a string with the chip name
        """
        return self._name

    @property
    def current_limit(self):
        """
        This property allows to get or set the current limitation of the chip. Allowed range is from 6 to 15 (mA)
        """
        return int.from_bytes(Object(0xe0c4).read(), "big")

    @current_limit.setter
    def current_limit(self, val: int):
        if val < 6 or val > 15:
            raise ValueError(
                'Current limitation is not supported. Should be between 6 and 15 mA, you have {0}'.format(val)
            )
        Object(0xe0c4).write(bytes([val]))

    @property
    def sleep_activation_delay(self):
        """
        This property allows to get or set the sleep activation delay for your chip. Should be from 1 to 255.
        (time the chip should wait after all operations are finished before going to sleep)
        """
        return int.from_bytes(Object(0xe0c3).read(), "big")

    @sleep_activation_delay.setter
    def sleep_activation_delay(self, val: int):
        if val < 1 or val > 255:
            raise ValueError(
                'Sleep activation value is not supported. Should be between 1 and 255 mA, you have {0}'.format(val)
            )
        Object(0xe0c3).write(bytes([val]))

    @property
    def uid(self):
        """
        This property allows to get a Coprocessor Unique ID. It will be returned as a namedtuple class. Example ::

            UID(cim_id='cd', platform_id='16', model_id='33', rommask_id='9301', chip_type='001c00050000',
                batch_num='0a09a413000a', x_coord='007d', y_coord='003b', fw_id='80101071', fw_build='2440')

        """
        _uid = Object(0xe0c2).read(force=True)
        uid = UID(cim_id=_uid[0:1].hex(),
                  platform_id=_uid[1:2].hex(),
                  model_id=_uid[2:3].hex(),
                  rommask_id=_uid[3:5].hex(),
                  chip_type=_uid[5:11].hex(),
                  batch_num=_uid[11:17].hex(),
                  x_coord=_uid[17:19].hex(),
                  y_coord=_uid[19:21].hex(),
                  fw_id=_uid[21:25].hex(),
                  fw_build=_uid[25:27].hex())
        return uid

    @property
    def global_lifecycle_state(self):
        """
        This property allows to get or set the global lifecycle state for your chip.
        Should be one of :data:`optigatrust.lifecycle_states`
        """
        return lifecycle_states[int.from_bytes(Object(0xe0c0).read(), 'big')]

    @global_lifecycle_state.setter
    def global_lifecycle_state(self, val: str):
        if val not in lifecycle_states.values():
            raise ValueError(
                'Wrong lifecycle state. Expected {0}, your provided {1}'.format(lifecycle_states, val)
            )
        for _, state in lifecycle_states.items():
            if state == val:
                Object(0xe0c0).write(bytes(state))

    @property
    def security_status(self):
        """
        This property allows to get the security status for your chip.
        """
        return int.from_bytes(Object(0xe0c1).read(), "big")

    @property
    def security_event_counter(self):
        """
        This property allows to get the security event counter for your chip.
        """
        return int.from_bytes(Object(0xe0c5).read(), "big")

    @property
    def security_monitor(self):
        """
        This property allows to get the security monitor configuration for your chip.

        .. note:: Only OPTIGA™ Trust M3 relevant

        """
        return int.from_bytes(Object(0xe0c9).read(), "big")

    def config_security_monitor(self, t_max=5, max_sec_credit=5, delayed_sec_sync=1):
        """
        This property allows to configure the security monitor configuration for your chip.

        .. note:: Only OPTIGA™ Trust M3 relevant

        .. warning:: Changing the following settings should be carefully evaluated as this might lead to security risks

        :param t_max:
            Chip allows to perform one protected operation per t_max.
            If more performed, internal SECcredit and afterwards SECcounter are increased until saturation. In the end
            the chip starts inducing delays of t_max between crypto operations
            t_max = 0 disables Security Monitor

        :param max_sec_credit:
            The maximum SECcredit that can be achieved

        :param delayed_sec_sync:
            If there are multiple security events with in t_max due to use case demand,
            the number of NVM write operations can be avoided by configuring this count appropriately

        """
        config = bytes()
        config += bytes([t_max])
        config += bytes([0])
        config += bytes([max_sec_credit])
        config += bytes([0])
        config += bytes([delayed_sec_sync])
        Object(0xe0c9).write(config)

    def protected_update(self, manifest, fragments):
        """
        This function helps to use the protected update feature of the chip

        :param manifest:
            The Manifest is a top level construct that ties all other structures together and is signed by an authorized
            entity whose identity is represented by a trust anchor installed at the OPTIGA™. See Portected Update in the
            Solution Reference Manual

        :param fragments
            Data streams used for the actual data update. fragments should be a list, where all the fragments are
            sorted in the order they should be transmitted to the chip. Each fragment should be bytes

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.api

        if not isinstance(manifest, bytes) and not isinstance(manifest, bytearray):
            raise TypeError("manifest should be bytes type")

        if not isinstance(fragments, list) and not isinstance(fragments, list):
            raise TypeError("fragments should be bytes type")

        for fragment in fragments:
            if not isinstance(fragment, bytes) and not isinstance(fragment, bytearray):
                raise TypeError("Each fragment should be bytes type")

        _backend.protected_update(api, manifest, fragments)

    def __str__(self):
        header = "=============================================="
        top = "Guessed chip name: {0}\n".format(self.name)
        fw_id = '{0:<30}{1:^10}:{2}\n'.format("Firmware Identifier", "[dwFirmwareIdentifier]", self.uid.fw_id)
        fw_build = '{0:<30}{1:^10}:{2}\n'.format("Build Number", "[rgbESWBuild]", self.uid.fw_build)
        current_limit = '{0:<30}{1:^10}:{2}\n'.format("Current Limitation", "[OID: 0xE0C4]", hex(self.current_limit))
        sleep_delay = '{0:<30}{1:^10}:{2}\n'.format("Sleep Activation Delay", "[OID: 0xE0C3]",
                                                    hex(self.sleep_activation_delay))
        lcsg = '{0:<30}{1:^10}:{2}\n'.format("Global Lifecycle State", "[OID: 0xE0C0]", self.global_lifecycle_state)
        sec_status = '{0:<30}{1:^10}:{2}\n'.format("Security Status", "[OID: 0xE0C1]", hex(self.security_status))
        sec_counter = '{0:<30}{1:^10}:{2}\n'.format("Security Event Counter", "[OID: 0xE0C5]",
                                                    hex(self.security_event_counter))

        return header + top + fw_id + fw_build + current_limit + sleep_delay + lcsg + sec_status + sec_counter


lifecycle_states = {
    0x01: 'creation',
    0x03: 'initialization',
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
    'meta_update': 0xd8,
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

_reset_types = {
    # Setting the LcsO of either a key or data object.
    'lcso_to_creation': 0x01,
    'lcso_to_initialisation': 0x03,
    'lcso_to_operational': 0x07,
    'lcso_to_termination': 0x0f,
    # - Flushing of either a key or data object with zero and set the used length of data objects, if present, to 0x0000
    # - If none of the flushing options is set in metadata, then the SetObjectProtected Manifest setting (if present)
    # gets used.
    # - In case of a key object the algorithm associated gets cleared and sets again with successful generation or
    # writing (protected update) a new key.
    'flushing': 0x10,
    # - Overwriting either a key or data object with random values and set the used length of data objects,
    # if present, to 0x0000.
    # - If none of the flushing options is set in metadata, then the SetObjectProtected Manifest setting
    # (if present) gets used.
    # - In case of a key object the algorithm associated gets cleared and sets again with successful generation or
    # writing (protected update) a new key
    'random_data': 0x20
}

_reset_types_swaped = {y: x for x, y in _reset_types.items()}


def _parse_version(tag_size, meta_itr):
    if tag_size == 2:
        value = int((next(meta_itr) << 8) + next(meta_itr))
        is_valid = bool((value >> 15) & 0x01)
        value &= value & 0x7fff
    else:
        raise ValueError(
            'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
        )
    return [is_valid, value]


def _parse_access_conditions(tag_size, meta_itr):
    access_conditions = list()
    i = 0
    while i < tag_size:
        _id = next(meta_itr)
        i += 1
        if _id in _access_conditions_ids_swaped:
            # Conf, Int, auto and luc have as the last two bytes a reference to the oid used for the expression
            # it is just another OID from the system
            if _id in (_access_conditions_ids['conf'], _access_conditions_ids['int'],
                       _access_conditions_ids['auto'], _access_conditions_ids['luc']):
                access_conditions.append(_access_conditions_ids_swaped[_id])
                access_conditions.append(hex(next(meta_itr)))
                access_conditions.append(hex(next(meta_itr)))
                i += 2
            elif _id in (_access_conditions_ids['sec_sta_a'], _access_conditions_ids['sec_sta_g']):
                access_conditions.append(_access_conditions_ids_swaped[_id])
                access_conditions.append(hex(next(meta_itr)))
                i += 1
            else:
                access_conditions.append(_access_conditions_ids_swaped[_id])
        # if we didn't meet the number, it should be in the lifecycle states
        elif _id in lifecycle_states:
            access_conditions.append(lifecycle_states[_id])
        else:
            access_conditions.append(hex(_id))
    if tag_size == 1:
        access_conditions = ''.join(access_conditions)

    return access_conditions


# pylint: disable=unused-argument
# we keep it for consistent API
def _parse_lifecycle_state(tag_size, meta_itr):
    lcso = next(meta_itr)
    if lcso not in lifecycle_states:
        raise ValueError(
            'Algorithm tag value {0} not found in supported {1}'.format(lcso, lifecycle_states)
        )
    return lifecycle_states[lcso]


# pylint: disable=unused-argument
# we keep it for consistent API
def _parse_key_usage(tag_size: int, meta_itr) -> list:
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

    return tag_data


# pylint: disable=unused-argument
# we keep it for consistent API
def _parse_algorithm(tag_size, meta_itr):
    algorithm = next(meta_itr)
    if algorithm not in _algorithms_swaped:
        raise ValueError(
            'Algorithm tag value {0} not found in supported {1}'.format(algorithm, _algorithms_swaped)
        )
    return _algorithms_swaped[algorithm]


# pylint: disable=unused-argument
# we keep it for consistent API
def _parse_reset_type(tag_size, meta_itr):
    reset_type_bytes = next(meta_itr)
    tag_data = list()
    reset_type_bytes_lower_nibble = reset_type_bytes & 0x0f
    if reset_type_bytes_lower_nibble == _reset_types['lcso_to_initialisation']:
        tag_data.append('lcso_to_initialisation')
    if reset_type_bytes_lower_nibble == _reset_types['lcso_to_creation']:
        tag_data.append('lcso_to_creation')
    if reset_type_bytes_lower_nibble == _reset_types['lcso_to_operational']:
        tag_data.append('lcso_to_operational')
    if reset_type_bytes_lower_nibble == _reset_types['lcso_to_termination']:
        tag_data.append('lcso_to_termination')

    if reset_type_bytes & _reset_types['flushing']:
        tag_data.append('flushing')
    if reset_type_bytes & _reset_types['random_data']:
        tag_data.append('random_data')

    return tag_data


# pylint: disable=unused-argument
# we keep it for consistent API
def _parse_type(tag_size, meta_itr):
    object_type = next(meta_itr)
    if object_type not in _data_object_types_swaped:
        raise ValueError(
            'Type tag value {0} not found in supported {1}'.format(object_type, _data_object_types_swaped)
        )
    return _data_object_types_swaped[object_type]


def _parse_used_max_size(tag_size: int, meta_itr) -> int:
    if tag_size == 2:
        value = int((next(meta_itr) << 8) + next(meta_itr))
    elif tag_size == 1:
        value = int(next(meta_itr))
    else:
        raise ValueError(
            'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
        )
    return value


_parser_map = {
    'used_size': _parse_used_max_size,
    'max_size': _parse_used_max_size,
    'type': _parse_type,
    'reset_type': _parse_reset_type,
    'algorithm': _parse_algorithm,
    'key_usage': _parse_key_usage,
    'lcso': _parse_lifecycle_state,
    'change': _parse_access_conditions,
    'execute': _parse_access_conditions,
    'read': _parse_access_conditions,
    'meta_update': _parse_access_conditions,
    'version': _parse_version
}


def _parse_raw_meta(raw_meta: bytes or bytearray):
    """
    This function should process the given metadata and return it in a human readable form.

    :ivar raw_meta:
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
    if not isinstance(raw_meta, bytes) and not isinstance(raw_meta, bytearray):
        raise TypeError(
            'Metadata (meta) should be in bytes form, you provided {0}'.format(type(raw_meta))
        )
    meta_tuple = tuple(raw_meta)
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
    if meta_size < 0 or meta_size > 62:
        raise ValueError(
            'Metadata size can\'t be less than zero and more than 64. Ou have {0}'.format(meta_size)
        )
    meta_parsed = dict()
    try:
        while True:
            tag = _meta_tags_swaped[next(meta_itr)]
            tag_size = next(meta_itr)
            if tag_size == 0:
                warnings.warn('Somehow the tag size for {0} was calculated as 0. Skip.'.format(tag))
                return None
            if tag_size < 0:
                raise ValueError(
                    'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
                )
            if tag not in _parser_map:
                raise ValueError(
                    'Parser for your tag [{0}] is not found'.format(tag)
                )
            meta_parsed[tag] = _parser_map[tag](tag_size, meta_itr)
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
        if element in ('int', 'conf', 'auto', 'luc'):
            _meta = [
                _access_conditions_ids[element],
                int(next(value_iter), 16),
                int(next(value_iter), 16),
            ]
        elif element in ('sec_sta_g', 'sec_sta_a'):
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


# ToDo: Add a test to test a key usage assignment
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
        1,  # size
        key_usage  # value
    ]

    return meta


# ToDo: Add a test to test a reset type assignment
def _prepare_reset_type(key, value) -> int and list:
    reset_type = 0
    # the value should be of type list()
    if not isinstance(value, list):
        raise TypeError(
            'reset type tag should be provided in the form of a list for instance [\'x\', \'y\', \'z\']'
        )
    for i in value:
        if i not in _reset_types:
            raise ValueError(
                'reset type isn\'t supported. Supported values {0}, you provided {1}'.format(_reset_types, i)
            )
        reset_type |= _reset_types[i]

    meta = [
        _meta_tags[key],  # key
        1,  # size
        reset_type  # value
    ]

    return meta


def _prepare_lcso(key, value) -> list:
    if value not in _lifecycle_states_swaped:
        raise ValueError(
            'Value for Lifecycle State meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_lifecycle_states_swaped.keys(), value)
        )
    meta = [
        _meta_tags[key],  # key
        1,  # size
        _lifecycle_states_swaped[value]  # value
    ]

    return meta


def _prepare_type(key, value) -> list:
    if value not in _data_object_types:
        raise ValueError(
            'Value for Type meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_data_object_types.keys(), value)
        )
    meta = [
        _meta_tags[key],  # key
        1,  # size
        _data_object_types[value]  # value
    ]

    return meta


def _prepare_meta_and_size(key, value) -> list:
    # This is how the result should look like
    # key  size  value
    # Used size and max size tags can't be send to the chip, so ignore them with a warning
    if key in ('used_size', 'max_size', 'algorithm'):
        print('Tag \'{0}\' cannot be defined by a user. Skip.'.format(key))
        return list()
    # Parse each key, and construct a
    if key == 'type':
        meta = _prepare_type(key, value)
    elif key == 'lcso':
        meta = _prepare_lcso(key, value)
    elif key == 'key_usage':
        meta = _prepare_key_usage(key, value)
    elif key == 'reset_type':
        meta = _prepare_reset_type(key, value)
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
            _meta_tags[key],  # key
            1,  # size
            _access_conditions_ids[value]  # value
        ]
    return meta


def _prepare_raw_meta(new_meta: dict) -> bytearray:
    """
    This function takes as an imput json-like formatted dictionary and translates it to the data to write into the chip

    :ivar new_meta:
        A dictionary (json like formatted) with new metadata; e.g.::

            {
                "lcso": "creation",
                "change": [
                    "lcso",
                    "<",
                    "operational"
                ],
                "execute": "always",
                "algorithm": "secp384r1",
                "key_usage": "0x21"
            }

    :vartype new_meta: dict

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

    return bytearray(meta)


class Object:
    """
    A class used to represent an Object on the OPTIGA Trust Chip

    :param id: the id of the object; e.g. 0xe0e0
    :type id: int

    :param updated: This boolean variable notifies whether metadata or data has been updated and this can bu used to
                   notify other modules to reread data if needed
    :type updated: bool
    """

    # pylint: disable=invalid-name
    # id is a valid name here
    def __init__(self, object_id):
        """
        This class

        :param object_id:
            an Object ID which you would like to initialise; e.g. 0xe0e0
        :type object_id: int
        """
        self.id = object_id
        self._optiga = Chip()
        # A flag to understand whether the object was recently updated
        self.updated = False

    @property
    def meta(self):
        """ A dictionary of the metadata present right now on the chip for the given object. It is writable,
        so user can update the metadata assigning the value to it. Example return ::

            {
                "lcso": "creation",
                "change": [
                    "lcso",
                    "<",
                    "operational"
                ],
                "execute": "always",
                "algorithm": "secp384r1",
                "key_usage": "0x21"
            }
        """
        _array_meta = self.read_raw_meta()
        return _parse_raw_meta(_array_meta)

    @meta.setter
    def meta(self, new_meta: dict):
        meta = _prepare_raw_meta(new_meta)
        self.write_raw_meta(meta)

    @property
    def used_size(self):
        """ Every object on the chip which can store data should have used_size property. Cannot be updated.
        """
        if 'used_size' in self.meta:
            return self.meta['used_size']

        warnings.warn("Object doesn't have used_size property.")
        return None

    @property
    def max_size(self):
        """ Every object on the chip which can store data should have max_size property. Cannot be updated.
        """
        if 'max_size' in self.meta:
            return self.meta['max_size']

        warnings.warn("Object doesn't have max_size property.")
        return None

    def read(self, offset=0, force=False) -> bytearray:
        """
        This function helps to read the data stored on the chip

        :param offset:
            An optional parameter defining whether you want to read the data with offset
        :type offset: int

        :param force:
            This is a :class:`bool` parameter which can be used to try to read the data even if id can't be found

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :return:
            byte string
        """

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        if force is False:
            if self.id not in self._optiga.object_id_values:
                raise TypeError(
                    "object_id not found. \n\r Supported = {0},\n\r  "
                    "Provided = {1}".format(list(hex(self._optiga.object_id)), self.id))

        return _backend.read_data(self._optiga.api, self.id, offset)

    def write(self, data, offset=0):
        """
        This function helps to write the data onto the chip

        :param data:
            byte string to write

        :param offset:
            An optional parameter defining whether you want to read the data with offset
        :type offset: int

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if self.id not in self._optiga.object_id_values:
            raise TypeError(
                "object_id not found. \n\r Supported = {0},\n\r  "
                "Provided = {1}".format(list(hex(self._optiga.object_id)), self.id))

        if len(data) > 1700:
            raise ValueError("length of data exceeds the limit of 1700")

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        _backend.write_data(self._optiga.api, self.id, offset, data)

        self.updated = True

    def read_raw_meta(self) -> bytearray:
        """
        This function helps to read the metadata associated with the data object stored on the chip

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :returns:
            byte string
        """
        if (self.id not in self._optiga.object_id_values) and (self.id not in self._optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self._optiga.object_id)),
                    list(hex(self._optiga.key_id)),
                    self.id)
            )

        return _backend.read_meta(self._optiga.api, self.id)

    def write_raw_meta(self, data):
        """
        This function helps to write the metadata associated with the data object stored on the chip

        :param data:
            byte string to write

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if (self.id not in self._optiga.object_id_values) and (self.id not in self._optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self._optiga.object_id)),
                    list(hex(self._optiga.key_id)),
                    self.id)
            )

        _backend.write_meta(self._optiga.api, self.id, data)

        self.updated = True
