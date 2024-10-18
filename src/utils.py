#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utility helper functions."""

import socket


def get_hostname() -> str:
    """Return hostname of th fqdn."""
    hostname = socket.gethostname()
    if "." in hostname:
        return hostname

    addrinfo = socket.getaddrinfo(
        hostname, None, family=socket.AF_UNSPEC, flags=socket.AI_CANONNAME
    )
    for addr in addrinfo:
        fqdn = addr[3]
        if fqdn and fqdn != "localhost":
            return fqdn

    return hostname
