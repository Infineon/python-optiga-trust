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

from enum import IntEnum


class Rng(IntEnum):
    TRNG = 0
    DRNG = 1


class Curves(IntEnum):
    SECP256R1 = 0x03
    NISTP256R1 = 0x03
    SECP384R1 = 0x04
    NISTP384R1 = 0x04


class KeyUsage(IntEnum):
    AUTH = 0x01
    ENCRYPT = 0x02
    SIGN = 0x10
    KEY_AGR = 0x20


class ObjectId(IntEnum):
    IFX_CERT = 0xE0E0
    USER_CERT_1 = 0xe0e1
    USER_CERT_2 = 0xE0E2
    USER_CERT_3 = 0xE0E3
    TRUST_ANCHOR_1 = 0xE0E8
    TRUST_ANCHOR_2 = 0xE0EF
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
    # Counters from 0 to 3
    COUNTER_0 = 0xe120
    COUNTER_1 = 0xe121
    COUNTER_2 = 0xe122
    COUNTER_3 = 0xe123
    # Platform Binding Secret
    PLAT_BIND_SECRET = 0xe140


class KeyId(IntEnum):
    ECC_KEY_E0F0 = 0xE0F0
    ECC_KEY_E0F1 = 0xE0F1
    ECC_KEY_E0F2 = 0xE0F2
    ECC_KEY_E0F3 = 0xE0F3
    RSA_KEY_E0FC = 0xe0fc
    RSA_KEY_E0FD = 0xe0fd

    # Key from Session context id 1
    SESSION_ID_1 = 0xE100
    # Key from Session context id 2
    SESSION_ID_2 = 0xE101
    # Key from Session context id 3
    SESSION_ID_3 = 0xE102
    # Key from Session context id 4
    SESSION_ID_4 = 0xE103

