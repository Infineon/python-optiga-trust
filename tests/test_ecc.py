import pytest
from optigatrust.asymmetric import *
import logging

LOGGER = logging.getLogger(__name__)


def test_keypair_default():
    LOGGER.info('Generate a keypair using default parameters')
    k = EccKey(0xe0f1).generate()
    assert isinstance(k.pkey, bytes)
    assert len(k.pkey) > 0
    assert len(k.pkey) == 68
    assert isinstance(k.curve, str)


@pytest.mark.parametrize("oid, curve, pub_key_size", [
    (0xe0f1, 'secp256r1', 68), (0xe0f1, 'secp384r1', 100), (0xe0f1, 'secp521r1', 137),
    (0xe0f1, 'brainpoolp256r1', 68), (0xe0f1, 'brainpoolp384r1', 100), (0xe0f1, 'brainpoolp512r1', 133),
    (0xe0f2, 'secp256r1', 68), (0xe0f2, 'secp384r1', 100), (0xe0f2, 'secp521r1', 137),
    (0xe0f2, 'brainpoolp256r1', 68), (0xe0f2, 'brainpoolp384r1', 100), (0xe0f2, 'brainpoolp512r1', 133),
    (0xe0f3, 'secp256r1', 68), (0xe0f3, 'secp384r1', 100), (0xe0f3, 'secp521r1', 137),
    (0xe0f3, 'brainpoolp256r1', 68), (0xe0f3, 'brainpoolp384r1', 100), (0xe0f3, 'brainpoolp512r1', 133),
    (0xE100, 'secp256r1', 68), (0xE100, 'secp384r1', 100), (0xE100, 'secp521r1', 137),
    (0xE100, 'brainpoolp256r1', 68), (0xE100, 'brainpoolp384r1', 100), (0xE100, 'brainpoolp512r1', 133),
    (0xE101, 'secp256r1', 68), (0xE101, 'secp384r1', 100), (0xE101, 'secp521r1', 137),
    (0xE101, 'brainpoolp256r1', 68), (0xE101, 'brainpoolp384r1', 100), (0xE101, 'brainpoolp512r1', 133),
    (0xE102, 'secp256r1', 68), (0xE102, 'secp384r1', 100), (0xE102, 'secp521r1', 137),
    (0xE102, 'brainpoolp256r1', 68), (0xE102, 'brainpoolp384r1', 100), (0xE102, 'brainpoolp512r1', 133),
    (0xE103, 'secp256r1', 68), (0xE103, 'secp384r1', 100), (0xE103, 'secp521r1', 137),
    (0xE103, 'brainpoolp256r1', 68), (0xE103, 'brainpoolp384r1', 100), (0xE103, 'brainpoolp512r1', 133)
])
def test_keypair_x_y(oid, curve, pub_key_size):
    LOGGER.info('Generate a keypair on {0} slot using {1} curve'.format(hex(oid), curve))
    k = EccKey(oid).generate(curve=curve)
    assert isinstance(k.pkey, bytes)
    assert len(k.pkey) > 0
    assert len(k.pkey) == pub_key_size
    assert k.id == oid
    assert k.curve == curve


def test_keypair_faulty():
    LOGGER.info('Try to use faulty curves and keyid')
    with pytest.raises(ValueError):
        EccKey(0xe0f1).generate(curve='secp384')

    with pytest.raises(ValueError):
        EccKey(0xe0fc).generate(curve='secp384r1')
