#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config builder for Consul."""

import socket

from pydantic import BaseModel, Field


class Ports(BaseModel):
    """Ports used in consul."""

    dns: int = Field(default=8600)
    http: int = Field(default=8500)
    https: int = Field(default=-1)
    grpc: int = Field(default=-1)
    grpc_tls: int = Field(default=-1)
    serf_lan: int = Field(default=8301)
    serf_wan: int = Field(default=8302)
    server: int = Field(default=8300)
    sidecar_min_port: int = Field(default=21000)
    sidecar_max_port: int = Field(default=21255)
    expose_min_port: int = Field(default=21500)
    expose_max_port: int = Field(default=21755)


class ConsulConfigBuilder:
    """Build the configuration file for consul."""

    def __init__(
        self,
        bind_address: str | None,
        datacenter: str,
        consul_servers: list[str],
        ports: Ports,
    ):
        self.bind_address = bind_address or "0.0.0.0"
        self.datacenter = datacenter
        self.consul_servers = consul_servers
        self.ports = ports

    def build(self) -> dict:
        """Build consul client config file.

        Service mesh, UI, DNS, gRPC, Serf WAN are not supported
        and disabled.
        """
        return {
            "bind_addr": self.bind_address,
            "datacenter": self.datacenter,
            "node_name": socket.gethostname(),
            "ports": {
                "dns": self.ports.dns,
                "http": self.ports.http,
                "https": self.ports.https,
                "grpc": self.ports.grpc,
                "grpc_tls": self.ports.grpc_tls,
                "serf_lan": self.ports.serf_lan,
                "serf_wan": self.ports.serf_wan,
                "server": self.ports.server,
            },
            "retry_join": self.consul_servers,
        }
