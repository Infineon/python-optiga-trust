#!/usr/bin/env python

# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import logging, textwrap

DEFAULT_LOG_LEVEL = logging.WARN


class MultiLineFormatter(logging.Formatter):
    def format(self, record):
        message = str(record.msg)
        record.msg = ""
        header = super().format(record)
        msg = textwrap.indent(message, " " * len(header)).lstrip()
        record.msg = message
        return header + msg


class Logger(logging.Logger):
    def __init__(self, name, level=None):
        if level is None:
            level = DEFAULT_LOG_LEVEL
        super().__init__(name, level)
        self.extra_info = None

        formatter = MultiLineFormatter(fmt="%(levelname)-8s %(name)-20s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        log_handler = logging.StreamHandler()
        log_handler.setFormatter(formatter)
        self.addHandler(log_handler)


def print_binary(binary_data):
    print(binary_to_hex(binary_data))


def binary_to_hex(binary_data):
    if not isinstance(binary_data, bytes):
        binary_data = bytes(binary_data)

    output = ""
    for i in range(len(binary_data)):
        if i > 0:
            if i % 16 == 0:
                output += "\n"
            else:
                output += " "
        output += binary_data[i : i + 1].hex()

    return output
