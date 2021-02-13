import pytest
from optigatrust import Object, x509, crypto, port

import logging

LOGGER = logging.getLogger(__name__)


def test_meta_read_certificate():
    LOGGER.info('Read metatadata of a certificate object')
    obj = x509.Certificate(0xe0e0)
    print(obj.meta)


def test_meta_read_key_meta():
    LOGGER.info('Read metatadata of a key object')
    obj = crypto.ECCKey(0xe0f0)
    print(obj.meta)
    obj = crypto.RSAKey(0xe0fc)
    print(obj.meta)


def test_meta_read_appdata():
    LOGGER.info('Read metatadata of an Application Data object')
    obj = Object(0xf1d0)
    print(obj.meta)


def test_meta_read_all_oids():
    LOGGER.info('Read metatadata of all possible objects')
    print(port.to_json())


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


def test_meta_assign_read_ac():
    LOGGER.info('Assign read never access conditions to an object and try to read')
    obj = Object(0xf1d0)
    old_meta = {'read': obj.meta['read']}
    obj.meta = {'read': 'never'}
    with pytest.raises(IOError):
        print(obj.read())

    obj.meta = old_meta


def test_meta_assign_change_ac():
    LOGGER.info('Assign change never access conditions to an object and try to change')
    obj = Object(0xf1d0)
    old_meta = {'change': obj.meta['change']}
    obj.meta = {'change': 'never'}
    with pytest.raises(IOError):
        print(obj.write(b'\x00\x00\x00'))

    obj.meta = old_meta


def test_meta_assign_execute_ac():
    LOGGER.info('Assign execute never access conditions to an object and try to sign data')
    obj = crypto.ECCKey(0xe0f0)
    old_meta = {'execute': obj.meta['execute']}
    obj.meta = {'execute': 'never'}
    with pytest.raises(IOError):
        print(obj.ecdsa_sign(b'\x00\x00\x00'))

    obj.meta = old_meta


def test_meta_check_max_size():
    LOGGER.info('Check Max Size Tag is integer')
    obj = Object(0xf1d0)
    assert 140 == obj.meta['max_size']


def test_meta_check_used_size():
    LOGGER.info('Check Used Size Tag is integer')
    obj = Object(0xf1d0)
    assert isinstance(obj.meta['used_size'], int)


def test_meta_assign_max_size():
    LOGGER.info('Check Max Size Tag cannot be assigned')
    obj = Object(0xf1d0)
    with pytest.raises(OSError):
        obj.meta = {'max_size': 100}


def test_meta_assign_used_size():
    LOGGER.info('Check Used Size Tag cannot be assigned')
    obj = Object(0xf1d0)
    with pytest.raises(OSError):
        obj.meta = {'used_size': 100}


@pytest.mark.parametrize("curve", (
    'secp256r1',
    'secp384r1',
    'secp521r1',
    'brainpoolp256r1',
    'brainpoolp384r1',
    'brainpoolp512r1'
))
def test_meta_check_algorithm_ecc(curve):
    LOGGER.info('Check Algorithm Tag is one of listed. ECC.')
    obj = crypto.ECCKey(0xe0f1)
    obj.generate_pair(curve=curve)
    assert curve == obj.meta['algorithm']


@pytest.mark.parametrize("key_size", (
    1024,
    2048
))
def test_meta_check_algorithm_rsa(key_size):
    LOGGER.info('Check Algorithm Tag is one of listed. RSA.')
    obj = crypto.RSAKey(0xe0fc)
    obj.generate_pair(key_size=key_size)
    assert ('rsa' + str(key_size)) == obj.meta['algorithm']


def test_meta_check_key_usage_ecc():
    LOGGER.info('Check Proper Key Usage Selection. ECC.')
    obj = crypto.ECCKey(0xe0f1)
    obj.generate_pair(key_usage=['signature', 'authentication'])
    assert ['signature', 'authentication'] == obj.meta['key_usage'] or \
           ['authentication', 'signature'] == obj.meta['key_usage']


def test_meta_check_key_usage_rsa():
    LOGGER.info('Check Proper Key Usage Selection. RSA.')
    obj = crypto.RSAKey(0xe0fc)
    obj.generate_pair(key_usage=['key_agreement', 'encryption'])
    assert ['key_agreement', 'encryption'] == obj.meta['key_usage'] or \
           ['encryption', 'key_agreement'] == obj.meta['key_usage']


@pytest.mark.parametrize("obj_type", [
    'byte_string',
    'up_counter',
    'trust_anchor',
    'device_cert',
    'pre_sh_secret',
    'platform_binding',
    'update_secret',
    'authorization_ref'
])
def test_meta_set_object_type(obj_type):
    LOGGER.info('Assign a new type to an an object; '
                'i.e. {0} and check whether it has been correctly set'.format(obj_type))
    obj = Object(0xf1d0)
    old_meta = None
    if 'type' in obj.meta:
        old_meta = {'type': obj.meta['type']}
    obj.meta = {'type': obj_type}

    assert obj.meta['type'] == obj_type

    if old_meta is not None:
        obj.meta = old_meta


@pytest.mark.parametrize("ki", [
    {'read': 'always'},
    {'change': 'always'},
    {'execute': 'always'},
    {'change': ['sec_sta_g', '0x20']},
    {'change': ['conf', '0xe1', '0x40']},
    {'read': ['conf', '0xe1', '0x40']},
    {'execute': ['conf', '0xe1', '0x40']},
    {'change': ['conf', '0xf1', '0xd0', '&&', 'int', '0xf1', '0xd0']},
    {'change': ['int', '0xe1', '0x40']},
    {'read': ['int', '0xe1', '0x40']},
    {'execute': ['int', '0xe1', '0x40']},
    {'change': ['int', '0xe0', '0xef']},
    {'read': ['auto', '0xf1', '0xd0']},
    {'execute': ['luc', '0xe1', '0x20']},
    {'change': ['lcsg', '<', 'operational']},
    {'change': ['sec_sta_a', '0x20']},
    {'change': ['lcsa', '<', 'operational']},
    {'change': ['lcso', '<', 'operational']},
    {'change': ['lcso', '==', 'operational']},
    {'change': ['lcso', '>', 'operational']},
    {'change': ['conf', '0xf1', '0xd0', '||', 'int', '0xf1', '0xd0']},
    {'read': 'never'},
    {'change': 'never'},
    {'execute': 'never'},
])
def test_meta_assign_complex_ac(ki):
    LOGGER.info('Assign complex access conditions {0} to an object and '
                'try to check whether they were correctly set'.format(ki))
    obj = Object(0xf1d0)
    for key, value in ki.items():
        if key not in obj.meta:
            old_meta = {key: 'always'}
        else:
            old_meta = {key: obj.meta[key]}
        obj.meta = {key: value}
        assert {key: value} == {key: obj.meta[key]}
        obj.meta = old_meta


def test_meta_assign_wrong_tag():
    LOGGER.info('Assign a non-existing tag to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'write': 'never'}


def test_meta_assign_wrong_tag_value():
    LOGGER.info('Assign a non-existing tag value to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'change': 'nie'}
