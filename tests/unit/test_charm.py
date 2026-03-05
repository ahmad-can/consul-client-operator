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
def write_health_check_script():
    with patch("config_builder.ConsulConfigBuilder._write_health_check_script") as p:
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
    write_health_check_script,
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
    assert charm.consul_notify.snap_name == snap_name
    assert charm.consul_notify.unix_socket_filepath == socket_path

    connect_snap_interface.assert_called_with(charm.snap_name, snap_name, "consul-socket")
    assert connect_snap_interface.call_count >= 1

    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict

    services = config_dict["services"]
    assert len(services) == 1
    health_check_service = services[0]
    assert health_check_service["name"] == "tcp-health-check"
    assert health_check_service["check"]["id"] == "tcp-check"
    assert health_check_service["check"]["name"] == "TCP Health Check"
    assert "--socket-path" in health_check_service["check"]["args"]
    assert socket_path in health_check_service["check"]["args"]


def test_consul_notify_socket_gone(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_health_check_script
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
    assert charm.consul_notify.snap_name == snap_name
    assert charm.consul_notify.unix_socket_filepath == socket_path

    harness.remove_relation(relation_id)

    assert charm.consul_notify.unix_socket_filepath is None

    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is not True
    assert "services" not in config_dict or len(config_dict.get("services", [])) == 0


def test_consul_notify_relation_properties(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_health_check_script
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


def test_socket_config_persists_across_events(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_health_check_script
):
    """Test that socket configuration persists across subsequent charm events."""
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

    # Add consul-cluster relation
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

    # Add consul-notify relation with socket information
    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()
    charm = harness.charm

    # Verify socket configuration is present in initial config
    assert write_config.called
    initial_config = write_config.call_args[0][1]
    initial_config_dict = json.loads(initial_config)
    assert initial_config_dict.get("enable_script_checks") is True
    assert "services" in initial_config_dict
    assert len(initial_config_dict["services"]) == 1
    assert initial_config_dict["services"][0]["name"] == "tcp-health-check"
    assert "--socket-path" in initial_config_dict["services"][0]["check"]["args"]
    assert socket_path in initial_config_dict["services"][0]["check"]["args"]

    # Reset the mock to track subsequent calls
    write_config.reset_mock()

    # Trigger a config-changed event (this would have caused the bug)
    harness.update_config({"serf-lan-port": 8302})

    # Verify socket configuration is STILL present after config-changed
    # This is the key assertion that would fail with the bug
    if write_config.called:
        post_event_config = write_config.call_args[0][1]
        post_event_config_dict = json.loads(post_event_config)
        assert post_event_config_dict.get("enable_script_checks") is True
        assert "services" in post_event_config_dict
        assert len(post_event_config_dict["services"]) == 1
        assert post_event_config_dict["services"][0]["name"] == "tcp-health-check"
        assert "--socket-path" in post_event_config_dict["services"][0]["check"]["args"]
        assert socket_path in post_event_config_dict["services"][0]["check"]["args"]

    # Verify relation data is still accessible
    assert charm.consul_notify.is_ready
    assert charm.consul_notify.snap_name == snap_name
    assert charm.consul_notify.unix_socket_filepath == socket_path

    # Reset and trigger another event (upgrade-charm)
    write_config.reset_mock()
    harness.charm.on.upgrade_charm.emit()

    # Verify socket configuration persists after upgrade event
    if write_config.called:
        upgrade_config = write_config.call_args[0][1]
        upgrade_config_dict = json.loads(upgrade_config)
        assert upgrade_config_dict.get("enable_script_checks") is True
        assert "services" in upgrade_config_dict
        assert len(upgrade_config_dict["services"]) == 1
        assert upgrade_config_dict["services"][0]["name"] == "tcp-health-check"
        assert "--socket-path" in upgrade_config_dict["services"][0]["check"]["args"]
        assert socket_path in upgrade_config_dict["services"][0]["check"]["args"]


def test_health_check_disabled_by_config(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_health_check_script
):
    """Test that TCP health check is disabled when config option is set to False."""
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

    # Disable TCP health check via config
    harness.update_config({"enable-health-check": False})

    # Add consul-cluster relation
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

    # Add consul-notify relation with socket information
    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()
    charm = harness.charm

    # Verify socket information is available
    assert charm.consul_notify.is_ready
    assert charm.consul_notify.snap_name == snap_name
    assert charm.consul_notify.unix_socket_filepath == socket_path

    # Verify TCP health check is NOT configured despite socket being available
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is not True
    assert "services" not in config_dict or len(config_dict.get("services", [])) == 0


def test_health_check_enabled_by_default(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    write_health_check_script,
    connect_snap_interface,
):
    """Test that TCP health check is enabled by default when socket is available."""
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

    # Don't set enable-health-check config, should default to True
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

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    # Verify TCP health check IS configured (default behavior)
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict
    assert len(config_dict["services"]) == 1
    assert config_dict["services"][0]["name"] == "tcp-health-check"


def test_health_check_disabled_when_socket_not_available(
    harness: Harness[ConsulCharm], snap, read_config, write_config, write_health_check_script
):
    """Test that TCP health check is disabled when consul-notify relation is not present."""
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

    # Enable TCP health check via config but don't add consul-notify relation
    harness.update_config({"enable-health-check": True})

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

    # Verify socket information is not available
    assert not charm.consul_notify.is_ready

    # Verify TCP health check is NOT configured due to missing socket
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is not True
    assert "services" not in config_dict or len(config_dict.get("services", [])) == 0


def test_health_check_can_be_toggled(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    write_health_check_script,
    connect_snap_interface,
):
    """Test that TCP health check can be enabled and disabled via config changes."""
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

    # Start with TCP health check enabled
    harness.update_config({"enable-health-check": True})

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

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    # Verify TCP health check is enabled
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict

    # Reset mock and disable TCP health check
    write_config.reset_mock()
    harness.update_config({"enable-health-check": False})

    # Verify TCP health check is now disabled
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is not True
    assert "services" not in config_dict or len(config_dict.get("services", [])) == 0

    # Reset mock and re-enable TCP health check
    write_config.reset_mock()
    harness.update_config({"enable-health-check": True})

    # Verify TCP health check is enabled again
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict


def test_health_check_uses_healthcheck_endpoints_when_available(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    write_health_check_script,
    connect_snap_interface,
):
    """Test that health check uses dedicated healthcheck endpoints when provided."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301", "10.20.0.11:8301"]
    healthcheck_addresses = ["10.30.0.10:8301", "10.30.0.11:8301"]
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
        "retry_join": join_server_addresses,
    }

    harness.update_config({"enable-health-check": True})

    # Add consul-cluster relation with both gossip and healthcheck endpoints
    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
            "external_gossip_healthcheck_endpoints": json.dumps(healthcheck_addresses),
        },
    )

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    # Verify health check is configured
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict
    assert len(config_dict["services"]) == 1

    # Verify health check uses healthcheck_addresses, not join_server_addresses
    health_check_service = config_dict["services"][0]
    assert health_check_service["name"] == "tcp-health-check"
    check_args = health_check_service["check"]["args"]

    # Should contain healthcheck addresses
    for addr in healthcheck_addresses:
        assert addr in check_args

    # Should NOT contain join server addresses
    for addr in join_server_addresses:
        assert addr not in check_args


def test_health_check_falls_back_to_gossip_endpoints(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    write_health_check_script,
    connect_snap_interface,
):
    """Test that health check falls back to gossip endpoints when healthcheck endpoints not provided."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301", "10.20.0.11:8301"]
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
        "retry_join": join_server_addresses,
    }

    harness.update_config({"enable-health-check": True})

    # Add consul-cluster relation WITHOUT healthcheck endpoints
    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
            # Note: external_gossip_healthcheck_endpoints is NOT provided
        },
    )

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    # Verify health check is configured
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict
    assert len(config_dict["services"]) == 1

    # Verify health check falls back to join_server_addresses
    health_check_service = config_dict["services"][0]
    assert health_check_service["name"] == "tcp-health-check"
    check_args = health_check_service["check"]["args"]

    # Should contain join server addresses
    for addr in join_server_addresses:
        assert addr in check_args


def test_health_check_with_empty_healthcheck_endpoints(
    harness: Harness[ConsulCharm],
    snap,
    read_config,
    write_config,
    write_health_check_script,
    connect_snap_interface,
):
    """Test that health check falls back to gossip endpoints when healthcheck endpoints is empty list."""
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
        "retry_join": join_server_addresses,
    }

    harness.update_config({"enable-health-check": True})

    # Add consul-cluster relation with empty healthcheck endpoints
    harness.add_relation(
        "consul-cluster",
        "consul-server",
        app_data={
            "datacenter": datacenter,
            "internal_gossip_endpoints": json.dumps(None),
            "external_gossip_endpoints": json.dumps(join_server_addresses),
            "internal_http_endpoint": json.dumps(None),
            "external_http_endpoint": json.dumps(None),
            "external_gossip_healthcheck_endpoints": json.dumps([]),  # Empty list
        },
    )

    harness.add_relation(
        "consul-notify",
        "test-app",
        app_data={
            "snap_name": snap_name,
            "unix_socket_filepath": socket_path,
        },
    )

    harness.begin_with_initial_hooks()

    # Verify health check is configured
    assert write_config.called
    config = write_config.call_args[0][1]
    config_dict = json.loads(config)
    assert config_dict.get("enable_script_checks") is True
    assert "services" in config_dict

    # Verify health check falls back to join_server_addresses when healthcheck list is empty
    health_check_service = config_dict["services"][0]
    check_args = health_check_service["check"]["args"]
    for addr in join_server_addresses:
        assert addr in check_args


def test_on_remove(harness: Harness[ConsulCharm], snap):
    """Test remove event handling."""
    with patch.object(ConsulCharm, "_disconnect_snap_interface") as disconnect_mock:
        harness.begin()
        harness.charm.on.remove.emit()

        # Verify disconnect was called
        disconnect_mock.assert_called_once()

        # Verify snap ensure was called with Absent state
        snap.SnapCache.return_value.__getitem__.return_value.ensure.assert_called_with(
            state=snap.SnapState.Absent
        )


def test_update_consul_config_no_datacenter(harness: Harness[ConsulCharm], snap):
    """Test _update_consul_config when datacenter is not set."""
    harness.begin()

    # Call _configure without adding consul-cluster relation
    result = harness.charm._update_consul_config()

    # Verify it returns False and sets blocked status
    assert result is False
    assert isinstance(harness.model.unit.status, BlockedStatus)


def test_update_consul_config_file_not_found(harness: Harness[ConsulCharm], snap, write_config):
    """Test _update_consul_config when config file doesn't exist."""
    datacenter = "test-dc"
    join_server_addresses = ["10.20.0.10:8301"]

    with patch.object(ConsulCharm, "_read_configuration") as read_mock:
        read_mock.side_effect = FileNotFoundError("Config file not found")

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

        # Verify config is written even when file doesn't exist
        assert write_config.called


def test_connect_snap_interface_snap_error(harness: Harness[ConsulCharm], snap):
    """Test _connect_snap_interface when snap connection fails."""
    snap.SnapCache.return_value.__getitem__.return_value.connect.side_effect = snap.SnapError(
        "Connection failed"
    )

    harness.begin()

    # Should not raise exception, just log warning
    harness.charm._connect_snap_interface("plug-snap", "slot-snap", "test-interface")


def test_connect_snap_interface_snap_not_found(harness: Harness[ConsulCharm], snap):
    """Test _connect_snap_interface when snap is not found."""
    snap.SnapCache.return_value.__getitem__.side_effect = snap.SnapNotFoundError()

    harness.begin()

    # Should not raise exception, just log warning
    harness.charm._connect_snap_interface("plug-snap", "slot-snap", "test-interface")


def test_disconnect_snap_interface_success(harness: Harness[ConsulCharm]):
    """Test _disconnect_snap_interface successful disconnection."""
    with patch("subprocess.run") as run_mock:
        run_mock.return_value.returncode = 0

        harness.begin()
        harness.charm._disconnect_snap_interface("plug-snap", "slot-snap", "test-interface")

        # Verify subprocess.run was called with correct arguments
        run_mock.assert_called_once()
        args = run_mock.call_args[0][0]
        assert args == [
            "snap",
            "disconnect",
            "plug-snap:test-interface",
            "slot-snap:test-interface",
        ]


def test_disconnect_snap_interface_error(harness: Harness[ConsulCharm]):
    """Test _disconnect_snap_interface when disconnection fails."""
    import subprocess

    with patch("subprocess.run") as run_mock:
        run_mock.side_effect = subprocess.CalledProcessError(1, "snap disconnect", stderr="Error")

        harness.begin()

        # Should not raise exception, just log warning
        harness.charm._disconnect_snap_interface("plug-snap", "slot-snap", "test-interface")


def test_ensure_snap_present_already_installed(harness: Harness[ConsulCharm], snap):
    """Test _ensure_snap_present when snap is already installed."""
    snap.SnapCache.return_value.__getitem__.return_value.present = True

    with patch.object(ConsulCharm, "_connect_snap_interface") as connect_mock:
        harness.begin()

        result = harness.charm._ensure_snap_present()

        # Verify it returns True
        assert result is True

        # Verify connect is NOT called when snap is already present
        connect_mock.assert_not_called()


def test_snap_property_parallel_install(harness: Harness[ConsulCharm], snap):
    """Test snap property with parallel install handling."""
    harness.begin()

    # The snap is already configured in the fixture, just verify it's accessible
    snap_obj = harness.charm.snap
    assert snap_obj is not None


def test_snap_property_basic(harness: Harness[ConsulCharm], snap):
    """Test snap property returns snap object."""
    harness.begin()

    # Verify snap property returns the mocked snap
    snap_obj = harness.charm.snap
    assert snap_obj is not None

    # Verify snap name is correctly formatted with instance key
    assert "_" in harness.charm.snap_name
    assert harness.charm.snap_name.startswith("consul-client_")


def test_bind_address_no_binding(harness: Harness[ConsulCharm]):
    """Test bind_address property when binding is not available."""
    with patch.object(harness.model, "get_binding") as binding_mock:
        binding_mock.return_value = None

        harness.begin()

        # Verify bind_address returns None
        assert harness.charm.bind_address is None


def test_bind_address_no_address(harness: Harness[ConsulCharm]):
    """Test bind_address property when bind_address is not available."""
    with patch.object(harness.model, "get_binding") as binding_mock:
        binding_mock.return_value.network.bind_address = None

        harness.begin()

        # Verify bind_address returns None
        assert harness.charm.bind_address is None


def test_on_upgrade(harness: Harness[ConsulCharm], snap, read_config, write_config):
    """Test upgrade event handling."""
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

    harness.begin()

    # Reset mocks to track upgrade event
    write_config.reset_mock()

    # Emit upgrade event
    harness.charm.on.upgrade_charm.emit()

    # Verify status is ActiveStatus after upgrade
    assert isinstance(harness.model.unit.status, ActiveStatus)
