#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config builder for Consul."""

import logging
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from utils import get_hostname

logger = logging.getLogger(__name__)


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
        health_check: bool,
        snap_name: str,
        consul_servers: list[str],
        ports: Ports,
        unix_socket_filepath: str | None = None,
        healthcheck_endpoints: list[str] | None = None,
        monitoring_interval: str = "10s",
        monitoring_samples: int = 3,
    ):
        self.bind_address = bind_address or "0.0.0.0"
        self.datacenter = datacenter
        self.health_check = health_check
        self.snap_name = snap_name
        self.consul_servers = consul_servers
        self.ports = ports
        self.unix_socket_filepath = unix_socket_filepath
        self.healthcheck_endpoints = healthcheck_endpoints
        self.monitoring_interval = monitoring_interval
        self.monitoring_samples = monitoring_samples

    def build(self) -> dict:
        """Build consul client config file.

        Service mesh, UI, DNS, gRPC, Serf WAN are not supported
        and disabled.
        """
        config = {
            "bind_addr": self.bind_address,
            "datacenter": self.datacenter,
            "node_name": get_hostname(),
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

        if self.health_check and self.unix_socket_filepath:
            self._write_health_check_script()
            config["enable_script_checks"] = True

            if self.healthcheck_endpoints:
                args = ["python3", str(self.consul_health_check), *self.healthcheck_endpoints]
            else:
                args = ["python3", str(self.consul_health_check), *self.consul_servers]
            args.extend(["--socket-path", self.unix_socket_filepath])
            args.extend(["--monitoring-samples", str(self.monitoring_samples)])

            config["services"] = [
                {
                    "name": "tcp-health-check",
                    "check": {
                        "id": "tcp-check",
                        "name": "TCP Health Check",
                        "args": args,
                        "interval": self.monitoring_interval,
                        "timeout": "5s",
                    },
                }
            ]
        return config

    def _write_health_check_script(self):
        """Copy the TCP health check Python script to the data directory."""
        health_check_script_path = Path(__file__).parent / "tcp_health_check.py"
        destination_path = self.consul_health_check
        logger.info(f"Creating parent directories for {Path(destination_path)} if does not exist")
        Path(destination_path).parent.mkdir(parents=True, exist_ok=True)

        if not destination_path.exists():
            try:
                shutil.copy(health_check_script_path, destination_path)
                logger.info(f"TCP health check script copied to {destination_path}")
            except Exception as e:
                logger.error(f"Failed to copy TCP health check script: {e}")
                raise

    @property
    def consul_health_check(self) -> Path:
        """Return the Consul TCP check script path."""
        return Path(f"/var/snap/{self.snap_name}/common/consul/data/tcp_health_check.py")
