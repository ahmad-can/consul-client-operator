# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
from unittest.mock import patch

import pytest
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness

from charm import ConsulCharm


@pytest.fixture()
def harness():
    harness = Harness(ConsulCharm)
    harness.add_network("10.10.0.10")
    yield harness
    harness.cleanup()


@pytest.fixture()
def snap():
    with patch("charm.snap") as p:
        yield p


@pytest.fixture()
def read_config():
    with patch.object(ConsulCharm, "_read_configuration") as p:
        yield p


@pytest.fixture()
def write_config():
    with patch.object(ConsulCharm, "_write_configuration") as p:
        yield p


@pytest.fixture()
def connect_snap_interface():
    with patch.object(ConsulCharm, "_connect_snap_interface") as p:
        yield p


@pytest.fixture()
def write_tcp_check_script():
    with patch("config_builder.ConsulConfigBuilder._write_tcp_check_script") as p:
        yield p


def test_start(harness: Harness[ConsulCharm], snap):
    harness.begin_with_initial_hooks()
    assert harness.model.unit.status == BlockedStatus("Integration consul-cluster missing")


def test_consul_cluster_relation(harness: Harness[ConsulCharm], snap, read_config, write_config):
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]
    read_config.return_value = {
        "bind_addr": "10.10.0.10",
        "datacenter": datacenter,
        "ports": {
            "dns": -1,
            "http": -1,
            "https": -1,
            "grpc": -1,
            "grpc_tls": -1,
            "serf_lan": 8301,
            "serf_wan": -1,
            "server": 8300,
        },
        "retry_join": [join_server_addresses],
    }

    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
        },
    )
    harness.begin_with_initial_hooks()
    assert harness.model.unit.status == ActiveStatus()


def test_consul_config_changed(harness: Harness[ConsulCharm], snap, read_config, write_config):
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]
    serf_lan_port = 9301

    harness.update_config({"serf-lan-port": serf_lan_port})
    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
        },
    )
    harness.begin_with_initial_hooks()
    assert harness.model.unit.status == ActiveStatus()

    config = write_config.mock_calls[0].args[1]
    config = json.loads(config)
    assert config.get("ports", {}).get("serf_lan") == serf_lan_port


def test_consul_notify_socket_available(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    connect_snap_interface,
    write_tcp_check_script,
):
    """Test consul-notify relation socket available event."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]
    snap_name = "test-snap"
    socket_path = "data/socket.sock"

    read_config.return_value = {
        "bind_addr": "10.10.0.10",
        "datacenter": datacenter,
        "ports": {
            "dns": -1,
            "http": -1,
            "https": -1,
            "grpc": -1,
            "grpc_tls": -1,
            "serf_lan": 8301,
            "serf_wan": -1,
            "server": 8300,
        },
        "retry_join": [join_server_addresses],
    }

    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
        },
    )

    _ = harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    assert harness.model.unit.status == ActiveStatus()

    charm = harness.charm
    assert charm.notify_snap_name == snap_name
    assert charm.unix_socket_filepath == socket_path

    connect_snap_interface.assert_called_with(charm.snap_name, snap_name, "consul-socket")
    assert connect_snap_interface.call_count >= 1

    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict

    services = config_dict["services"]
    assert len(services) == 1
    tcp_check_service = services[0]
    assert tcp_check_service["name"] == "tcp-health-check"
    assert tcp_check_service["check"]["id"] == "tcp-check"
    assert tcp_check_service["check"]["name"] == "TCP Health Check"
    assert "--socket-path" in tcp_check_service["check"]["args"]
    assert socket_path in tcp_check_service["check"]["args"]


def test_consul_notify_socket_gone(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_tcp_check_script
):
    """Test consul-notify relation socket gone event."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]
    snap_name = "test-snap"
    socket_path = "data/socket.sock"

    read_config.return_value = {
        "bind_addr": "10.10.0.10",
        "datacenter": datacenter,
        "ports": {
            "dns": -1,
            "http": -1,
            "https": -1,
            "grpc": -1,
            "grpc_tls": -1,
            "serf_lan": 8301,
            "serf_wan": -1,
            "server": 8300,
        },
        "retry_join": [join_server_addresses],
    }

    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
        },
    )

    relation_id = harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    charm = harness.charm
    assert charm.notify_snap_name == snap_name
    assert charm.unix_socket_filepath == socket_path

    harness.remove_relation(relation_id)

    assert charm.unix_socket_filepath is None

    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is not True
    assert "services" not in config_dict or len(config_dict.get("services", [])) == 0


def test_consul_notify_relation_properties(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_tcp_check_script
):
    """Test consul-notify relation properties and is_ready functionality."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]
    snap_name = "test-snap"
    socket_path = "data/socket.sock"

    read_config.return_value = {
        "bind_addr": "10.10.0.10",
        "datacenter": datacenter,
        "ports": {
            "dns": -1,
            "http": -1,
            "https": -1,
            "grpc": -1,
            "grpc_tls": -1,
            "serf_lan": 8301,
            "serf_wan": -1,
            "server": 8300,
        },
        "retry_join": [join_server_addresses],
    }

    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
        },
    )

    harness.begin_with_initial_hooks()

    charm = harness.charm
    assert not charm.consul_notify.is_ready

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    assert charm.consul_notify.is_ready
    assert charm.consul_notify.snap_name == snap_name
    assert charm.consul_notify.unix_socket_filepath == socket_path
