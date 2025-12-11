# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for tcp_health_check module."""

import json
import socket
from unittest.mock import MagicMock, call, patch

import pytest

from tcp_health_check import NetworkStatus, send_nic_down_alert, tcp_check


class TestNetworkStatus:
    """Test NetworkStatus enum."""

    def test_nic_down_value(self):
        """Test that NIC_DOWN has the correct value."""
        assert NetworkStatus.NIC_DOWN.value == "nic-down"


class TestSendNicDownAlert:
    """Test send_nic_down_alert function."""

    @patch("tcp_health_check.socket.socket")
    @patch("tcp_health_check.time.time")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_down_alert_success(self, mock_time, mock_socket_class):
        """Test successful NIC down alert sending."""
        mock_time.return_value = 1234567890.123
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "ok"}'

        send_nic_down_alert("data/socket.sock")

        # Verify socket was created with correct parameters
        mock_socket_class.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)

        # Verify connection to correct path
        mock_sock.connect.assert_called_once_with("/snap/data/data/socket.sock")

        # Verify message was sent
        assert mock_sock.sendall.called
        sent_data = mock_sock.sendall.call_args[0][0]
        message = json.loads(sent_data.decode())

        assert message["version"] == "1.0"
        assert message["timestamp"] == 1234567890.123
        assert message["status"] == "nic-down"

        # Verify response was received
        mock_sock.recv.assert_called_once_with(1024)

    @patch("tcp_health_check.socket.socket")
    @patch("tcp_health_check.time.time")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_down_alert_error_response(self, mock_time, mock_socket_class, caplog):
        """Test handling of error response from server."""
        mock_time.return_value = 1234567890.123
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "error", "message": "Test error"}'

        send_nic_down_alert("data/socket.sock")

        # Should log the error message
        assert "Error from server: Test error" in caplog.text

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_down_alert_socket_error(self, mock_socket_class, caplog):
        """Test handling of socket connection error."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")

        send_nic_down_alert("data/socket.sock")

        # Should log the socket error
        assert "Socket error: Connection refused" in caplog.text

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_down_alert_general_exception(self, mock_socket_class, caplog):
        """Test handling of general exception."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = Exception("Unexpected error")

        send_nic_down_alert("data/socket.sock")

        # Should log the error
        assert "Error sending alert signal: Unexpected error" in caplog.text

    @patch("tcp_health_check.socket.socket")
    @patch("tcp_health_check.time.time")
    @patch.dict("os.environ", {"SNAP_DATA": "/var/snap/consul/common"})
    def test_send_nic_down_alert_different_snap_data(self, mock_time, mock_socket_class):
        """Test that SNAP_DATA environment variable is respected."""
        mock_time.return_value = 1234567890.123
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "ok"}'

        send_nic_down_alert("socket.sock")

        # Verify correct path is used
        mock_sock.connect.assert_called_once_with("/var/snap/consul/common/socket.sock")


class TestTcpCheck:
    """Test tcp_check function."""

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_all_servers_reachable(self, mock_create_connection, caplog):
        """Test when all servers are reachable."""
        servers = ["10.0.0.1:8301", "10.0.0.2:8301", "10.0.0.3:8301"]
        mock_create_connection.return_value.__enter__ = MagicMock()
        mock_create_connection.return_value.__exit__ = MagicMock()

        tcp_check(servers, "data/socket.sock")

        # Verify all servers were checked
        assert mock_create_connection.call_count == 3
        # Verify the actual connection calls (ignoring __enter__/__exit__)
        connection_calls = [
            call
            for call in mock_create_connection.call_args_list
            if call[0]  # Only calls with positional arguments
        ]
        assert len(connection_calls) == 3
        assert connection_calls[0] == call(("10.0.0.1", 8301), timeout=5)
        assert connection_calls[1] == call(("10.0.0.2", 8301), timeout=5)
        assert connection_calls[2] == call(("10.0.0.3", 8301), timeout=5)

        # Verify success message
        assert "✅ All servers reachable. No alert triggered." in caplog.text

    @patch("tcp_health_check.send_nic_down_alert")
    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_one_server_unreachable(
        self, mock_create_connection, mock_send_alert, caplog
    ):
        """Test when one server is unreachable."""
        servers = ["10.0.0.1:8301", "10.0.0.2:8301"]

        # First server succeeds, second fails
        def side_effect(*args, **kwargs):
            if args[0] == ("10.0.0.1", 8301):
                mock_conn = MagicMock()
                mock_conn.__enter__ = MagicMock()
                mock_conn.__exit__ = MagicMock()
                return mock_conn
            else:
                raise socket.timeout("Connection timed out")

        mock_create_connection.side_effect = side_effect

        # Use monitoring_samples=1 for immediate alert
        tcp_check(servers, "data/socket.sock", monitoring_samples=1)

        # Verify alert was sent
        mock_send_alert.assert_called_once_with("data/socket.sock")
        assert "TCP check failed for 10.0.0.2:8301" in caplog.text

    @patch("tcp_health_check.send_nic_down_alert")
    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_all_servers_unreachable(
        self, mock_create_connection, mock_send_alert, caplog
    ):
        """Test when all servers are unreachable."""
        servers = ["10.0.0.1:8301", "10.0.0.2:8301"]
        mock_create_connection.side_effect = socket.error("Connection refused")

        # Use monitoring_samples=1 for immediate alert
        tcp_check(servers, "data/socket.sock", monitoring_samples=1)

        # Verify alert was sent
        mock_send_alert.assert_called_once_with("data/socket.sock")
        assert "TCP check failed for 10.0.0.1:8301" in caplog.text
        assert "TCP check failed for 10.0.0.2:8301" in caplog.text

    @patch("tcp_health_check.send_nic_down_alert")
    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_socket_timeout(self, mock_create_connection, mock_send_alert, caplog):
        """Test handling of socket timeout."""
        servers = ["10.0.0.1:8301"]
        mock_create_connection.side_effect = socket.timeout("Timed out")

        # Use monitoring_samples=1 for immediate alert
        tcp_check(servers, "data/socket.sock", monitoring_samples=1)

        # Verify alert was sent
        mock_send_alert.assert_called_once_with("data/socket.sock")
        assert "TCP check failed for 10.0.0.1:8301" in caplog.text

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_no_socket_path_on_failure(self, mock_create_connection, caplog):
        """Test when server fails but no socket path is provided."""
        servers = ["10.0.0.1:8301"]
        mock_create_connection.side_effect = socket.error("Connection refused")

        # Use monitoring_samples=1 to reach threshold immediately
        tcp_check(servers, None, monitoring_samples=1)

        # Verify error message about missing socket path
        assert "Cannot send alert: socket_path is required but was not provided" in caplog.text

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_single_server(self, mock_create_connection, caplog):
        """Test with a single server."""
        servers = ["192.168.1.10:9301"]
        mock_create_connection.return_value.__enter__ = MagicMock()
        mock_create_connection.return_value.__exit__ = MagicMock()

        tcp_check(servers, "data/socket.sock")

        # Verify server was checked
        mock_create_connection.assert_called_once_with(("192.168.1.10", 9301), timeout=5)
        assert "TCP check successful for 192.168.1.10:9301" in caplog.text

    @patch("tcp_health_check.send_nic_down_alert")
    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_mixed_results(self, mock_create_connection, mock_send_alert, caplog):
        """Test with multiple servers having mixed success/failure results."""
        servers = ["10.0.0.1:8301", "10.0.0.2:8301", "10.0.0.3:8301"]

        results = [
            MagicMock(__enter__=MagicMock(), __exit__=MagicMock()),  # Success
            socket.error("Connection refused"),  # Failure
            MagicMock(__enter__=MagicMock(), __exit__=MagicMock()),  # Success
        ]

        def side_effect(*args, **kwargs):
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        mock_create_connection.side_effect = side_effect

        # Use monitoring_samples=1 for immediate alert
        tcp_check(servers, "data/socket.sock", monitoring_samples=1)

        # Verify alert was sent (because at least one failed)
        mock_send_alert.assert_called_once_with("data/socket.sock")
        assert "TCP check successful for 10.0.0.1:8301" in caplog.text
        assert "TCP check failed for 10.0.0.2:8301" in caplog.text
        assert "TCP check successful for 10.0.0.3:8301" in caplog.text

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_different_ports(self, mock_create_connection, caplog):
        """Test with servers on different ports."""
        servers = ["10.0.0.1:8301", "10.0.0.2:9301", "10.0.0.3:7301"]
        mock_create_connection.return_value.__enter__ = MagicMock()
        mock_create_connection.return_value.__exit__ = MagicMock()

        tcp_check(servers, "data/socket.sock")

        # Verify correct ports were used
        connection_calls = [
            call
            for call in mock_create_connection.call_args_list
            if call[0]  # Only calls with positional arguments
        ]
        assert len(connection_calls) == 3
        assert connection_calls[0] == call(("10.0.0.1", 8301), timeout=5)
        assert connection_calls[1] == call(("10.0.0.2", 9301), timeout=5)
        assert connection_calls[2] == call(("10.0.0.3", 7301), timeout=5)

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_ipv6_address(self, mock_create_connection, caplog):
        """Test with IPv6 addresses."""
        servers = ["[::1]:8301", "[2001:db8::1]:8301"]

        # Note: The current implementation splits on ':' which won't work correctly
        # with IPv6 addresses. This test documents the current behavior.
        # In a real scenario, this would need to be fixed.
        with pytest.raises((ValueError, OSError)):
            tcp_check(servers, "data/socket.sock")
