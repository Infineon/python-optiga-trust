# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import logging

LOGGER = logging.getLogger(__name__)


def test_chip_control_set_current_limit(chip):
    chip.current_limit = 6
    chip.current_limit = 15
    print(chip.security_event_counter)
    print(chip.uid)
    print(chip.name)
    print(chip.global_lifecycle_state)
    print(chip.sleep_activation_delay)
    print(chip.security_monitor)
    print(chip.security_status)


def test_chip_control_set_wrong_current_limit(chip):
    with pytest.raises(ValueError):
        chip.current_limit = 0

    with pytest.raises(ValueError):
        chip.current_limit = 20
