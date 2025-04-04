#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm the application.

This charm deploys consul agent as client on machines (hosts or VMs).
The charm is related to consul-k8s operator where consul server running
on kubernetes. The charm receives consul server addresses via the relation
to join the consul cluster.
"""

import hashlib
import json
import logging
import re
import subprocess
import typing
from pathlib import Path

import charms.operator_libs_linux.v2.snap as snap
from charms.consul_client.v0.consul_notify import ConsulNotifyProvider
from charms.consul_k8s.v0.consul_cluster import ConsulEndpointsRequirer
from ops import main
from ops.charm import CharmBase
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

from config_builder import ConsulConfigBuilder, Ports

logger = logging.getLogger(__name__)

CONSUL_SNAP_NAME = "consul-client"
CONSUL_EXTRA_BINDING = "consul"
CONSUL_SOCKET_INTERFACE = "consul-socket"
SNAP_INSTANCE_KEY_REGEX_PATTERN = r"^[a-z0-9]{1,10}$"


class ConsulCharm(CharmBase):
    """Charm the application."""

    def __init__(self, *args):
        super().__init__(*args)

        # Add instance key to snap name for parallel snap installs
        # Hash of unit name is used as snap instance key
        # Instance key cannot be more than 10 characters
        snap_instance_key = hashlib.shake_256(self.model.unit.name.encode("utf-8")).hexdigest(5)
        self.snap_name = f"{CONSUL_SNAP_NAME}_{snap_instance_key}"
        logger.info(f"consul snap name is aliased as {self.snap_name}")

        self.ports: Ports = self.get_consul_ports()
        self.consul = ConsulEndpointsRequirer(charm=self)
        self.consul_notify = ConsulNotifyProvider(charm=self)

        self.notify_snap_name: str | None = None
        self.unix_socket_filepath: str | None = None

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.upgrade_charm, self._on_upgrade)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.consul.on.endpoints_changed, self._on_consul_cluster_endpoints_changed
        )
        self.framework.observe(self.consul_notify.on.socket_available, self._on_socket_available)
        self.framework.observe(self.consul_notify.on.socket_gone, self._on_socket_gone)

    def get_consul_ports(self) -> Ports:
        """Return consul ports with supported values."""
        ports = {
            "dns": -1,
            "http": -1,
            "https": -1,
            "grpc": -1,
            "grpc_tls": -1,
            "serf_lan": self.config.get("serf-lan-port"),
            "serf_wan": -1,
            "server": 8300,
            "sidecar_min_port": 0,
            "sidecar_max_port": 0,
            "expose_min_port": 0,
            "expose_max_port": 0,
        }

        return Ports(**ports)

    def _on_install(self, _):
        self._ensure_snap_present()

    def _on_start(self, _):
        self.unit.status = MaintenanceStatus(f"Starting {self.snap_name} snap")
        self._configure()

    def _on_stop(self, _):
        self.unit.status = MaintenanceStatus(f"Stopping {self.snap_name} snap")
        self._configure()

    def _on_remove(self, _) -> None:
        self.unit.status = MaintenanceStatus(f"Uninstalling {self.snap_name} snap")
        try:
            self._disconnect_snap_interface(
                self.snap_name, self.notify_snap_name, CONSUL_SOCKET_INTERFACE
            )
            self.snap.ensure(state=snap.SnapState.Absent)
            logging.debug(f"Unininstalling snap {self.snap_name}")
        except snap.SnapError as e:
            logger.info(f"Failed to uninstall {self.snap_name}: {str(e)}")
            self._update_status(BlockedStatus(f"Failed to remove {self.snap_name}"))

    def _on_upgrade(self, _):
        self._ensure_snap_present()
        self._configure()

    def _on_config_changed(self, _):
        self._ensure_snap_present()
        self._configure()

    def _on_consul_cluster_endpoints_changed(self, _):
        self._configure()

    def _on_socket_available(self, _):
        if self.consul_notify.is_ready:
            self.notify_snap_name = self.consul_notify.snap_name
            self.unix_socket_filepath = self.consul_notify.unix_socket_filepath
            logger.info(
                f"Socket information available for sending NIC down alert: snap={self.notify_snap_name}, socket={self.unix_socket_filepath}"
            )

            self._connect_snap_interface(
                self.snap_name, self.notify_snap_name, CONSUL_SOCKET_INTERFACE
            )

            self._configure()

    def _on_socket_gone(self, _):
        self.unix_socket_filepath = None
        logger.info("Socket information gone, disabling TCP health check")

        self._configure()

    def _update_status(self, status):
        if self.unit.is_leader():
            self.app.status = status
        self.unit.status = status

    def _configure(self):
        if self._wait_for_mandatory_relations():
            return

        config_changed = self._update_consul_config()
        if config_changed:
            try:
                self.snap.restart(services=["consul"])
            except snap.SnapError as e:
                logger.info(f"Failed to restart {self.snap_name}: {str(e)}")
                self._update_status(BlockedStatus(f"Failed to restart {self.snap_name}"))
                return

        self._update_status(ActiveStatus())

    def _wait_for_mandatory_relations(self) -> bool:
        """Return true if mandatory relations are not joined."""
        # consul-cluster relation
        if not self.consul.datacenter and not self.consul.external_gossip_endpoints:
            logger.debug("Waiting for consul-cluster relation to be ready")
            self._update_status(BlockedStatus("Integration consul-cluster missing"))
            return True

        return False

    def _update_consul_config(self) -> bool:
        """Update consul client config."""
        if self.consul.datacenter and self.consul.external_gossip_endpoints:
            enable_tcp_check = self.consul_notify.is_ready

            constructed_consul_config = ConsulConfigBuilder(
                self.bind_address,
                self.consul.datacenter,
                enable_tcp_check,
                self.snap_name,
                self.consul.external_gossip_endpoints,
                self.ports,
                self.unix_socket_filepath,
            ).build()
        else:
            logger.debug("Waiting for consul server address from consul-cluster relation")
            self._update_status(BlockedStatus("Integration consul-cluster missing"))
            return False

        try:
            _running_consul_config = self._read_configuration(self.consul_config)
        except FileNotFoundError:
            logger.info("Cluster config file not present to read")
            _running_consul_config = ""
        if _running_consul_config == constructed_consul_config:
            return False

        self._write_configuration(
            self.consul_config, json.dumps(constructed_consul_config, indent=2)
        )
        logger.info("Consul configuration file updated.")

        return True

    def _connect_snap_interface(
        self, plug_snap: str, slot_snap: str | None, interface: str
    ) -> None:
        """Connect a snap interface between plug and slot snaps using snap library."""
        try:
            snap_cache = snap.SnapCache()
            snap_obj = snap_cache[plug_snap]

            snap_obj.connect(interface, service=slot_snap)
            logger.info(
                f"Successfully connected snap interfaces: {plug_snap}:{interface} -> {slot_snap}:{interface}"
            )
        except (snap.SnapError, snap.SnapNotFoundError) as e:
            logger.warning(f"Failed to connect snap interfaces: {e}")

    def _disconnect_snap_interface(
        self, plug_snap: str, slot_snap: str | None, interface: str
    ) -> None:
        """Disconnect a snap interface between plug and slot snaps."""
        plug = f"{plug_snap}:{interface}"
        slot = f"{slot_snap}:{interface}"
        cmd = ["snap", "disconnect", plug, slot]

        try:
            _ = subprocess.run(cmd, check=True, capture_output=True, text=True)
            logger.info(f"Successfully disconnected snap interfaces: {plug} -X- {slot}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to disconnect snap interfaces: {e.stderr}")

    def _ensure_snap_present(self) -> bool:
        """Install snap if it is not already present.

        Returns True is snap is installed/refreshed to desire version.
        """
        channel: str = self.model.config.get("snap-channel")  # pyright: ignore

        try:
            if not self.snap.present:
                self.snap.ensure(snap.SnapState.Latest, channel=channel)
                # Connect snap interfaces only after the snap is installed.
                # This avoids redundant connect calls when the snap is already present,
                # reducing unnecessary operations on every config change.
                self._connect_snap_interface(
                    self.snap_name, self.notify_snap_name, CONSUL_SOCKET_INTERFACE
                )
        except snap.SnapError as e:
            logger.info(f"Exception occurred while installing snap {self.snap_name}: {str(e)}")
            self._update_status(BlockedStatus(f"Failed to install snap {self.snap_name}"))
            return False
        return True

    def _read_configuration(self, filepath: Path):
        """Read contents of configuration file."""
        with open(filepath) as f:
            return f.read()

    def _write_configuration(self, path: Path, text: str) -> None:
        """Write text to configuration file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    @property
    def snap(self) -> snap.Snap:
        """Return the snap object for the Consul snap."""
        # This is handled in a property to avoid calls to snapd until they're necessary.
        _snap_cache = snap.SnapCache()

        # Snap library does not support parallel installs
        # https://github.com/canonical/operator-libs-linux/issues/134
        # Workaround to use the snap library with parallel installs
        try:
            return _snap_cache[self.snap_name]
        except snap.SnapNotFoundError as e:
            # Check if the snap name is parallel install with instance key
            name_key = self.snap_name.rsplit("_", 1)
            if not (len(name_key) == 2 and re.match(SNAP_INSTANCE_KEY_REGEX_PATTERN, name_key[1])):
                raise e

            name = name_key[0]
            info = _snap_cache._snap_client.get_snap_information(name)
            info = typing.cast(snap._SnapDict, info)

            _snap_cache._snap_map[self.snap_name] = snap.Snap(
                name=self.snap_name,
                state=snap.SnapState.Available,
                channel=info["channel"],
                revision=info["revision"],
                confinement=info["confinement"],
                apps=None,
            )
            # Setting snapd experimental parallel instances config to true
            snap._system_set("experimental.parallel-instances", "true")
            _s = _snap_cache._snap_map[self.snap_name]
            if _s is None:
                raise snap.SnapError("No snap exists in Snap cache") from None

            return _s

    @property
    def consul_config(self) -> Path:
        """Return the consul config path."""
        return Path(f"/var/snap/{self.snap_name}/common/consul/config/client.json")

    @property
    def consul_tcp_check(self) -> Path:
        """Return the path to the TCP health check script."""
        return Path(f"/var/snap/{self.snap_name}/common/consul/data/tcp_health_check.py")

    @property
    def bind_address(self) -> str | None:
        """Get address from consul network binding."""
        binding = self.model.get_binding(CONSUL_EXTRA_BINDING)
        if binding is None:
            return None

        address = binding.network.bind_address
        if address is None:
            return None

        return str(address)


if __name__ == "__main__":  # pragma: nocover
    main(ConsulCharm)  # type: ignore
