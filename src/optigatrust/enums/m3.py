#!/usr/bin/env python

# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""This module defines basic device tapes and enumerations of the optigatrust package"""
# pylint: skip-file

from enum import IntEnum


class Rng(IntEnum):
    TRNG = 0
    DRNG = 1


class Curves(IntEnum):
    SEC_P256R1 = 0x03
    SEC_P384R1 = 0x04
    SEC_P521R1 = 0x05
    BRAINPOOL_P256R1 = 0x13
    BRAINPOOL_P384R1 = 0x15
    BRAINPOOL_P512R1 = 0x16


class KeyUsage(IntEnum):
    AUTH = 0x01
    ENCRYPT = 0x02
    SIGN = 0x10
    KEY_AGR = 0x20


class ObjectId(IntEnum):
    IFX_CERT = 0xE0E0
    USER_CERT_1 = 0xE0E1
    USER_CERT_2 = 0xE0E2
    USER_CERT_3 = 0xE0E3
    TRUST_ANCHOR_1 = 0xE0E8
    TRUST_ANCHOR_2 = 0xE0E9
    TRUST_ANCHOR_3 = 0xE0EF
    DATA_SLOT_140B_0 = 0xF1D0
    DATA_SLOT_140B_1 = 0xF1D1
    DATA_SLOT_140B_2 = 0xF1D2
    DATA_SLOT_140B_3 = 0xF1D3
    DATA_SLOT_140B_4 = 0xF1D4
    DATA_SLOT_140B_5 = 0xF1D5
    DATA_SLOT_140B_6 = 0xF1D6
    DATA_SLOT_140B_7 = 0xF1D7
    DATA_SLOT_140B_8 = 0xF1D8
    DATA_SLOT_140B_9 = 0xF1D9
    DATA_SLOT_140B_A = 0xF1DA
    DATA_SLOT_140B_B = 0xF1DB
    # An Object OIDs to store arbitrary data type 2 (Refer to the solution reference manual)
    # 1500 bytes each
    DATA_SLOT_1500B_0 = 0xF1E0
    DATA_SLOT_1500B_1 = 0xF1E1
    LCSA = 0xF1C0
    APP_SEC_STATUS = 0xF1C1
    COPROC_UID = 0xE0C2
    # Global lifecycle state
    LCSG = 0xE0C0
    # Global security Status
    SEC_MONITOR_STATUS = 0xE0C1
    # Security Monitor Configuration
    SEC_MONITOR_CONF = 0xE0C9
    # Sleep Activation Delay
    SLEEP_DELAY = 0xE0C3
    # Current limit from 6 to 15 mA
    CURRENT_LIM = 0xE0C4
    # Security Event Counter
    SEC_CNTR = 0xE0C5
    # Maximum Communication Buffer Size
    MAX_COMM_BUFSIZE = 0xE0C6
    # Counters from 0 to 3
    COUNTER_0 = 0xE120
    COUNTER_1 = 0xE121
    COUNTER_2 = 0xE122
    COUNTER_3 = 0xE123
    # Platform Binding Secret
    PLAT_BIND_SECRET = 0xE140


class KeyId(IntEnum):
    ECC_KEY_E0F0 = 0xE0F0
    ECC_KEY_E0F1 = 0xE0F1
    ECC_KEY_E0F2 = 0xE0F2
    ECC_KEY_E0F3 = 0xE0F3
    RSA_KEY_E0FC = 0xE0FC
    RSA_KEY_E0FD = 0xE0FD
    AES_KEY_E200 = 0xE200


class SessionId(IntEnum):
    # Key from Session context id 1
    SESSION_ID_1 = 0xE100
    # Key from Session context id 2
    SESSION_ID_2 = 0xE101
    # Key from Session context id 3
    SESSION_ID_3 = 0xE102
    # Key from Session context id 4
    SESSION_ID_4 = 0xE103


def has_value(cls, value):
    return any(value == item.value for item in cls)
