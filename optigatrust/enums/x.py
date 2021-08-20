#!/usr/bin/env python
"""This module defines basic device tapes and enumerations of the optigatrust package """
# pylint: skip-file

from enum import IntEnum


class Rng(IntEnum):
    TRNG = 0
    DRNG = 1


class Curves(IntEnum):
    SECP256R1 = 0x03
    SECP384R1 = 0x04


class KeyUsage(IntEnum):
    AUTH = 0x01
    SIGN = 0x10
    KEY_AGR = 0x20


class ObjectId(IntEnum):
    IFX_CERT = 0xE0E0
    USER_CERT_1 = 0xe0e1
    USER_CERT_2 = 0xE0E2
    USER_CERT_3 = 0xE0E3
    TRUST_ANCHOR_1 = 0xE0E8
    TRUST_ANCHOR_2 = 0xE0EF
    DATA_SLOT_100B_0 = 0xF1D0
    DATA_SLOT_100B_1 = 0xF1D1
    DATA_SLOT_100B_2 = 0xF1D2
    DATA_SLOT_100B_3 = 0xF1D3
    DATA_SLOT_100B_4 = 0xF1D4
    DATA_SLOT_100B_5 = 0xF1D5
    DATA_SLOT_100B_6 = 0xF1D6
    DATA_SLOT_100B_7 = 0xF1D7
    DATA_SLOT_100B_8 = 0xF1D8
    DATA_SLOT_100B_9 = 0xF1D9
    DATA_SLOT_100B_A = 0xF1DA
    DATA_SLOT_100B_B = 0xF1DB
    DATA_SLOT_100B_C = 0xF1DC
    DATA_SLOT_100B_D = 0xF1DD
    DATA_SLOT_100B_E = 0xF1DE
    DATA_SLOT_100B_F = 0xF1DF
    # An Object OIDs to store arbitrary data type 2 (Refer to the solution reference manual)
    # 1500 bytes each
    DATA_SLOT_1500B_0 = 0xF1E0
    DATA_SLOT_1500B_1 = 0xF1E1
    LCSA = 0xF1C0
    APP_SEC_STATUS = 0xF1C1
    COPROC_UID = 0xE0C2
    # Global lifecycle state
    LCSG = 0xe0c0
    # Global security Status
    SEC_STATUS = 0xe0c1
    # Sleep Activation Delay
    SLEEP_DELAY = 0xe0c3
    # Current limit from 6 to 15 mA
    CURRENT_LIM = 0xe0c4
    # Security Event Counter
    SEC_CNTR = 0xe0c5
    # Maximum Communication Buffer Size
    MAX_COMM_BUFSIZE = 0xe0c6


class KeyId(IntEnum):
    # Key from key store
    ECC_KEY_E0F0 = 0xE0F0
    # Key from key store
    ECC_KEY_E0F1 = 0xE0F1
    # Key from key store
    ECC_KEY_E0F2 = 0xE0F2
    # Key from key store
    ECC_KEY_E0F3 = 0xE0F3


class SessionId(IntEnum):
    # Key from Session context id 1
    SESSION_ID_1 = 0xE100
    # Key from Session context id 2
    SESSION_ID_2 = 0xE101
    # Key from Session context id 3
    SESSION_ID_3 = 0xE102
    # Key from Session context id 4
    SESSION_ID_4 = 0xE103
