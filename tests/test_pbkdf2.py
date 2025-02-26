# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust.objects as objects
import optigatrust.crypto as optiga_crypto


@pytest.mark.parametrize(
    "password, salt, iterations, output",
    [
        (
            b"password",
            b"salt",
            1,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        ),
        (
            b"password",
            b"salt",
            2,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        ),
    ],
)
def test_pbkdf2_sha256(password, salt, iterations, output):
    app_data = objects.AppData(0xF1D0)
    app_data.write(password)
    old_type = app_data.meta["type"]
    app_data.meta = {"type": "pre_sh_secret"}

    result = optiga_crypto.pbkdf2_hmac(app_data, "sha256", salt, iterations, 32)

    app_data.meta = {"type": old_type}
    assert output == result.hex()


@pytest.mark.parametrize(
    "password, salt, iterations, output",
    [
        (
            b"password",
            b"salt",
            1,
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
        ),
        (
            b"password",
            b"salt",
            2,
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
        ),
    ],
)
def test_pbkdf2_sha512(password, salt, iterations, output):
    app_data = objects.AppData(0xF1D0)
    app_data.write(password)
    old_type = app_data.meta["type"]
    app_data.meta = {"type": "pre_sh_secret"}

    result = optiga_crypto.pbkdf2_hmac(app_data, "sha512", salt, iterations, 64)
    app_data.meta = {"type": old_type}

    assert output == result.hex()
