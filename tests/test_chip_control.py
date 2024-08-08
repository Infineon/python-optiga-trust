# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust as ot
import logging

LOGGER = logging.getLogger(__name__)


def test_chip_control_set_current_limit():
    optiga = ot.Chip()
    optiga.current_limit = 6
    optiga.current_limit = 15
    print(optiga.security_event_counter)
    print(optiga.uid)
    print(optiga.name)
    print(optiga.global_lifecycle_state)
    print(optiga.sleep_activation_delay)
    print(optiga.security_monitor)
    print(optiga.security_status)


def test_chip_control_set_wrong_current_limit():
    optiga = ot.Chip()

    with pytest.raises(ValueError):
        optiga.current_limit = 0

    with pytest.raises(ValueError):
        optiga.current_limit = 20
