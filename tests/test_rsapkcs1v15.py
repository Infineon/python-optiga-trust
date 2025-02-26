# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import os

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

from optigatrust import objects, crypto

import optigatrust as optiga

pytest.onek, pytest.onek_fail, pytest.twok, pytest.twok_fail = None, None, None, None
k1, k2 = None, None
pytest.tbs_str = bytes("Test String to Sign".encode())
pytest.tbs_str_fail = bytes("FAILED Test String to Sign".encode())
pytest.test_dir = os.path.dirname(__file__)


pytest.test_pkey_1024 = bytes.fromhex(
    "30819f300d06092a864886f70d010101050003818d0030818902818100daa6bbbfe2ed75a3b0b53ea1f69b78278b"
    "839fecec794e6211e580ddf05ddb1be5f646da4c12e0892cb1d7d1fb5d3db878bddcefa3d3faf650defa3523de57"
    "2c546a191320fa093021602f20906a2281ab56fb033cec004b35050767ae3ddc833be6d5e50b1ab3053772bb2b28"
    "d4e7ded1b76c962e1814aff12fba01c5118d910203010001"
)
pytest.test_key_1024 = bytes.fromhex(
    "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100daa6bbbfe2ed75a3b0"
    "b53ea1f69b78278b839fecec794e6211e580ddf05ddb1be5f646da4c12e0892cb1d7d1fb5d3db878bddcefa3d3fa"
    "f650defa3523de572c546a191320fa093021602f20906a2281ab56fb033cec004b35050767ae3ddc833be6d5e50b"
    "1ab3053772bb2b28d4e7ded1b76c962e1814aff12fba01c5118d9102030100010281807384232cfd76f6efc42bfd"
    "2b145e8edc5598f4a4f74a1f5f30954fbff17da484d8b98435507ba8a4d038250d8aff77dc3dee110b8a4234146e"
    "255f8b33a803e52dac342e737f687daa7bcb7e67e2881f3db6e9d5d18be16aa5de24cb3118a44721f9a44168f668"
    "2f5179df4bb96129ca6b28447b35357672bfa4805123711901024100f0d64aa62fa31db07085f083abe8754ff6b4"
    "9ef76c2af5be450ff2fa41df9fda7b75087652c09b2267f801e634286768554d731d9f8fb27375314d2d3664e5a3"
    "024100e86adc6ca63c36c2457c26fef017cc697ff2099d9831c238a77e3a7369bcb7edcad962ffe4e49d0c7fad77"
    "ed3b52558d848e881d46b853be36bc2d7f972ceb3b024048be412fef0592cb1f41a582efe2b7c45e5cf20303bdfa"
    "19ed5c42e4ca0ed486b671840bd134f1e6b3869a7440decf551926da9561039340026ed0c3ce412d8702402f82b0"
    "be9118dc04c899818b39df538cf977abd988641b94e3405d887c43f4c16a6717e2c192ae3c00d9a01b61b60a011c"
    "e8da104a05a230cf1596a36f6ee243024100bd346c0334c5b44bdc5ddb7353522f97af55f4f8025031d2717f273f"
    "2e30dd7976322cd6e48ff0cc5bc7db658094990efe8cc72bc26d1ce526a2960b933d2382"
)

pytest.test_pkey_2048 = bytes.fromhex(
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100cc69aa50400eb2b4d23ae724d4"
    "192e262cb2a4d508e325341bcea4e229a06ccbea4ac5e8ed19ba352163fa0cabe7e132f037e30616ff58cf18a1f5"
    "c6b0cac5b4e3182ee787648b4f1d00a2121ee2291c110b6a80c15f5274b7ea218bb71b694ab21aced79dd1045fc4"
    "b69e88ac3339c376fc1862b11c00ec26edea90e98416ee69f53f6eb14d221a9cb2a5c228ba040f2b6125e8fd8ce0"
    "9e200f17c4a73b20db4156f14186be4eaf2e6e1e568c71ea880f13def0a4b0ad79fa16d83ff487bb6befbb87e034"
    "b9e5445c53f78db92b0006fbbd0938ef735c9b7474fc56baeb23405df64ba066b36a2d2a191eef8c6f13cee7495a"
    "4c261a6ba487a0b741f0ebfeb90203010001"
)
pytest.test_key_2048 = bytes.fromhex(
    "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100cc69aa50400eb2b4"
    "d23ae724d4192e262cb2a4d508e325341bcea4e229a06ccbea4ac5e8ed19ba352163fa0cabe7e132f037e30616ff"
    "58cf18a1f5c6b0cac5b4e3182ee787648b4f1d00a2121ee2291c110b6a80c15f5274b7ea218bb71b694ab21aced7"
    "9dd1045fc4b69e88ac3339c376fc1862b11c00ec26edea90e98416ee69f53f6eb14d221a9cb2a5c228ba040f2b61"
    "25e8fd8ce09e200f17c4a73b20db4156f14186be4eaf2e6e1e568c71ea880f13def0a4b0ad79fa16d83ff487bb6b"
    "efbb87e034b9e5445c53f78db92b0006fbbd0938ef735c9b7474fc56baeb23405df64ba066b36a2d2a191eef8c6f"
    "13cee7495a4c261a6ba487a0b741f0ebfeb902030100010282010100b9370d0105e9cb7717fe132e4598433e87c5"
    "9ea1011a7fbd456ce9ed9af6275e64fe37712454e969f6c555ee615d0baa520af183b516cd6b68d067980edccc63"
    "6859a3365a7179e0c750a9896dbe52ad81ac2c6659d07b3012ecec5462274e32464b101c427cff4f9f3831517966"
    "38f2a93f270155a52018d9f53d52eca3a8f9e3273aeabd48af3db01215aecd4da7cc2879c01247328e3e732755cc"
    "f89721319502361f444ad225aa949a143a1dc132c54f6e0275464812858db732c4e1e4fd629e654ea460b175ef2a"
    "b43d80538b49eb8bc0ee9d76f697217762aeaad77cdbfb21ddeddeb142f446c0b7e30bec0c65fb2ef79a21f585d5"
    "e30c90f55852657902818100e788909cba12eac92b8322a9f966ad901d7d56c76bf51950b7550b5a1d73d115bc9d"
    "635f5b70afe3194f9fbb6db266fec8c5e162e96f2dfef83a823fe0269f6cb1dd0105424e150208ff4ed89188b42f"
    "32999da51b6234f9fe652710513467ccd3036c2c8f20092e3bfc4af7d1e65f755f6d53d726dc4ced8d3658a19695"
    "cfbf02818100e2036e9eae2cab1ed9b20f9d436bf9a7656579a24415b97c417acd0cfc7cb24f99e6d535447f2946"
    "7ab20671b73b12722a43bba7b45673dcee37eac5f5186873e239b70164fa4ff57b76c9bac3f0b52a28752154a28f"
    "7c76ab53c42d5780cf86a643aa975f0aba6465916e5b551b66750981aba06b8794ddd363c60ed710cf870281804b"
    "8f9a024c07987006af4944c78be6e0bd7f062f16e06a5e99363bfa30da7745ecc440860245886149055f4fbfc115"
    "33d93a1b1038b67c0055ea624f8e4b8c83e0980b9937c65bbcca4ae7e46dba7b735bc41e5a9fd13110d52115da91"
    "65d4ea57832a6e70573827ca93cfb388e0f20e501251e6495c640eb2a325d1b65f35e90281804a31aa3cb91cbcc8"
    "11dadc395a0ab617f7b74a28b4851530ef25eaee5a6c6cf4a8a71852b63bb0470cbc2855683b22210c32d40587b3"
    "e1b1231a841d9c09f9302191a4bbf6741d8f8e8a3e4aeb4bb78d315ed22440812df09ee98ebafbc0b35f96711c2d"
    "38ec02a83697794cce31827ee532062f515d5ec73b3fc3a2d783133d02818025b1091c9c9d20404106c40bc330a8"
    "da8dd32a7fec7a9a3d209d8644d32e1b46c6797918ccd8ff4887f0733202dda600580ed5fbce144f9d50077be990"
    "9d62ef9cd2b745c92144c8af16d30475ce09dcbbcfa7e94df4812233354322f391482531bca43dc7d42a95bcc41b"
    "79c96cfa9b203425b436aadfc705fd0fc4581763fe"
)


def setup_keys_1k():
    k1 = objects.RSAKey(0xE0FC)
    k2 = objects.RSAKey(0xE0FD)
    pytest.onek, _ = crypto.generate_pair(key_object=k1, key_size=1024)
    pytest.onek_fail, _ = crypto.generate_pair(key_object=k2, key_size=1024)
    return k1, k2


def setup_keys_2k():
    k1 = objects.RSAKey(0xE0FC)
    k2 = objects.RSAKey(0xE0FD)
    pytest.twok, _ = crypto.generate_pair(key_object=k1, key_size=2048)
    pytest.twok_fail, _ = crypto.generate_pair(key_object=k2, key_size=2048)
    return k1, k2


def test_rsassa_checkcopy():
    k1, _ = setup_keys_1k()
    crypto.pkcs1v15_sign(k1, pytest.tbs_str)


def test_rsassa_1k_sha256():
    k1, _ = setup_keys_1k()
    s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert s.hash_alg == "sha256"
    assert s.algorithm == "sha256_rsa"


def test_rsassa_2k_sha256():
    k1, _ = setup_keys_2k()
    s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert s.hash_alg == "sha256"
    assert s.algorithm == "sha256_rsa"


def test_rsassa_1k_sha384():
    k1, _ = setup_keys_1k()
    s = crypto.pkcs1v15_sign(key_object=k1, data=pytest.tbs_str, hash_algorithm="sha384")
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert s.hash_alg == "sha384"
    assert s.algorithm == "sha384_rsa"


def test_rsassa_2k_sha384():
    k1, _ = setup_keys_2k()
    s = crypto.pkcs1v15_sign(key_object=k1, data=pytest.tbs_str, hash_algorithm="sha384")
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert s.hash_alg == "sha384"
    assert s.algorithm == "sha384_rsa"


def test_1k_signverify():
    k1, k2 = setup_keys_1k()
    hash_name = "sha256"

    # Create signature
    signature = crypto.pkcs1v15_sign(k1, pytest.tbs_str).signature

    # Verify signature with cryptography package
    cryptography_public_key = serialization.load_der_public_key(pytest.onek)
    cryptography_public_key.verify(
        signature, pytest.tbs_str, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
    )

    # Assert wrong text
    with pytest.raises(InvalidSignature):
        cryptography_public_key.verify(
            signature, pytest.tbs_str_fail, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
        )

    # Assert wrong key
    with pytest.raises(InvalidSignature):
        cryptography_public_key = serialization.load_der_public_key(pytest.onek_fail)
        cryptography_public_key.verify(
            signature, pytest.tbs_str, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
        )


def test_2k_signverify():
    k1, k2 = setup_keys_2k()
    hash_name = "sha256"

    # Create signature
    signature = crypto.pkcs1v15_sign(k1, pytest.tbs_str).signature

    # Verify signature with cryptography package
    cryptography_public_key = serialization.load_der_public_key(pytest.twok)
    cryptography_public_key.verify(
        signature, pytest.tbs_str, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
    )

    # Assert wrong text
    with pytest.raises(InvalidSignature):
        cryptography_public_key.verify(
            signature, pytest.tbs_str_fail, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
        )

    # Assert wrong key
    with pytest.raises(InvalidSignature):
        cryptography_public_key = serialization.load_der_public_key(pytest.twok_fail)
        cryptography_public_key.verify(
            signature, pytest.tbs_str, padding.PKCS1v15(), crypto._hash_map[hash_name][2]
        )


def test_rsassa_nonkey_2():
    k1, _ = setup_keys_1k()
    with pytest.raises(TypeError):
        crypto.pkcs1v15_sign(k1, int(19273917398739829))


def test_pkcs1v15_encrypt_1024():
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, pytest.test_pkey_1024[18:])
    assert isinstance(ctext, bytes)


def test_pkcs1v15_encrypt_2048():
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, pytest.test_pkey_2048[19:], exp_size="2048")
    assert isinstance(ctext, bytes)


def test_pkcs1v15_encrypt_1024_oid():
    cert_obj_id = 0xE0EF
    new_cert = optiga.Object(cert_obj_id)
    old_content = new_cert.read()
    with open(os.path.join(pytest.test_dir, "fixtures/test-rsa1024-example-cert.crt"), "rb") as f:
        der_bytes = f.read()
        new_cert.write(der_bytes)
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, cert_obj_id)
    new_cert.write(old_content)
    assert isinstance(ctext, bytes)


def test_pkcs1v15_encrypt_2048_oid():
    cert_obj_id = 0xE0EF
    new_cert = optiga.Object(cert_obj_id)
    old_content = new_cert.read()
    with open(os.path.join(pytest.test_dir, "fixtures/test-rsa2048-example-cert.crt"), "rb") as f:
        der_bytes = f.read()
        new_cert.write(der_bytes)
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, cert_obj_id, exp_size="2048")
    new_cert.write(old_content)
    assert isinstance(ctext, bytes)


def test_pkcs1v15_encrypt_1024_fail():
    # Assert wrong public key format
    with pytest.raises(ValueError):
        crypto.pkcs1v15_encrypt(pytest.tbs_str, pytest.test_pkey_1024)


def test_pkcs1v15_encrypt_2048_fail():
    # Assert wrong public key format
    with pytest.raises(ValueError):
        crypto.pkcs1v15_encrypt(pytest.tbs_str, pytest.test_pkey_2048, exp_size="2048")


def test_pkcs1v15_encrypt_1024_oid_fail():
    cert_obj_id = 0xE0EF
    new_cert = optiga.Object(cert_obj_id)
    old_content = new_cert.read()
    with open(
        os.path.join(pytest.test_dir, "fixtures/test-rsa1024-corrupted-example-cert.crt"), "rb"
    ) as f:
        der_bytes = f.read()
        new_cert.write(der_bytes)
    with pytest.raises(OSError):
        crypto.pkcs1v15_encrypt(pytest.tbs_str, cert_obj_id)
    new_cert.write(old_content)


def test_pkcs1v15_encrypt_2048_oid_fail():
    cert_obj_id = 0xE0EF
    new_cert = optiga.Object(cert_obj_id)
    old_content = new_cert.read()
    with open(
        os.path.join(pytest.test_dir, "fixtures/test-rsa2048-corrupted-example-cert.crt"), "rb"
    ) as f:
        der_bytes = f.read()
        new_cert.write(der_bytes)
    with pytest.raises(OSError):
        crypto.pkcs1v15_encrypt(pytest.tbs_str, cert_obj_id, exp_size="2048")
    new_cert.write(old_content)


def test_pkcs1v15_encrypt_decrypt_1024_oid():
    # Prepare the setup
    key_id = 0xE0FC
    key_obj = objects.RSAKey(key_id)
    pkey, _ = crypto.generate_pair(key_obj, key_usage=["encryption"], key_size=1024)

    # Encrypt the data using just generated Public Key
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, pkey[18:], exp_size="1024")

    # Decrypt the cipher text with the private key stored on the chip
    ptext = crypto.pkcs1v15_decrypt(ctext, key_id)

    # Assert the result
    assert pytest.tbs_str == ptext


def test_pkcs1v15_encrypt_decrypt_2048_oid():
    # Prepare the setup
    key_id = 0xE0FC
    key_obj = objects.RSAKey(key_id)
    pkey, _ = crypto.generate_pair(key_obj, key_usage=["encryption"], key_size=2048)

    # Encrypt the data using just generated Public Key
    ctext = crypto.pkcs1v15_encrypt(pytest.tbs_str, pkey[19:], exp_size="2048")

    # Decrypt the cipher text with the private key stored on the chip
    ptext = crypto.pkcs1v15_decrypt(ctext, key_id)

    # Assert the result
    assert pytest.tbs_str == ptext
