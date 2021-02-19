import pytest
import optigatrust as ot
import logging

LOGGER = logging.getLogger(__name__)


def test_chip_control_set_current_limit():
    optiga = ot.Chip()
    optiga.current_limit = 6
    optiga.current_limit = 15
    optiga.security_event_counter()
    optiga.uid()
    optiga.name()
    optiga.global_lifecycle_state()
    optiga.sleep_activation_delay()
    optiga.security_monitor()
    optiga.security_status()


def test_chip_control_set_wrong_current_limit():
    optiga = ot.Chip()

    with pytest.raises(ValueError):
        optiga.current_limit = 0

    with pytest.raises(ValueError):
        optiga.current_limit = 20


