# SPDX-FileCopyrightText: 2021-2025 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest

import optigatrust as optiga


def pytest_addoption(parser):
    parser.addoption("--interface", action="store", default=None)
    print("Parameter interface used.")


@pytest.fixture(scope="session")
def interface(request):
    interface_value = request.config.option.interface
    return interface_value


@pytest.fixture(scope="session", autouse=True)
def chip(interface):
    print("Initializing chip with interface {}.".format(interface))
    return optiga.Chip(interface=interface)
