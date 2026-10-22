# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for tcp_health_check module."""

import json
import socket
from unittest.mock import MagicMock, call, patch

import pytest

from tcp_health_check import (
    NetworkStatus,
    read_state,
    send_nic_down_alert,
    send_nic_up_alert,
    tcp_check,
    write_state,
)


@pytest.fixture(autouse=True)
def _isolated_snap_data(tmp_path, monkeypatch):
    """Keep the default state file out of the real /tmp so tests don't leak into each other."""
    monkeypatch.setenv("SNAP_DATA", str(tmp_path))


class TestNetworkStatus:
    """Test NetworkStatus enum."""

    def test_nic_down_value(self):
        """Test that NIC_DOWN has the correct value."""
        assert NetworkStatus.NIC_DOWN.value == "nic-down"

    def test_nic_up_value(self):
        """Test that NIC_UP has the correct value."""
        assert NetworkStatus.NIC_UP.value == "nic-up"


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
        assert connection_calls[0] == call(("10.0.0.1", 8301), timeout=2)
        assert connection_calls[1] == call(("10.0.0.2", 8301), timeout=2)
        assert connection_calls[2] == call(("10.0.0.3", 8301), timeout=2)

        # Verify success message
        assert "Network is reachable on" in caplog.text

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
        assert "Network is not reachable on 10.0.0.2:8301" in caplog.text

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
        assert "Network is not reachable on 10.0.0.1:8301" in caplog.text
        assert "Network is not reachable on 10.0.0.2:8301" in caplog.text

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
        assert "Network is not reachable on 10.0.0.1:8301" in caplog.text

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
        mock_create_connection.assert_called_once_with(("192.168.1.10", 9301), timeout=2)
        assert "Network is reachable on 192.168.1.10:9301" in caplog.text

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
        assert "Network is reachable on 10.0.0.1:8301" in caplog.text
        assert "Network is not reachable on 10.0.0.2:8301" in caplog.text
        assert "Network is reachable on 10.0.0.3:8301" in caplog.text

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
        assert connection_calls[0] == call(("10.0.0.1", 8301), timeout=2)
        assert connection_calls[1] == call(("10.0.0.2", 9301), timeout=2)
        assert connection_calls[2] == call(("10.0.0.3", 7301), timeout=2)

    @patch("tcp_health_check.socket.create_connection")
    def test_tcp_check_ipv6_address(self, mock_create_connection, caplog):
        """Test with IPv6 addresses."""
        servers = ["[::1]:8301", "[2001:db8::1]:8301"]

        # Note: The current implementation splits on ':' which won't work correctly
        # with IPv6 addresses. This test documents the current behavior.
        # In a real scenario, this would need to be fixed.
        with pytest.raises((ValueError, OSError)):
            tcp_check(servers, "data/socket.sock")


class TestSendNicUpAlert:
    """Test send_nic_up_alert function."""

    @patch("tcp_health_check.socket.socket")
    @patch("tcp_health_check.time.time")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_up_alert_success(self, mock_time, mock_socket_class):
        """A nic-up message is sent and reported as delivered."""
        mock_time.return_value = 1234567890.123
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "success"}'

        assert send_nic_up_alert("hypervisor/shutdown.sock") is True

        mock_sock.connect.assert_called_once_with("/snap/data/hypervisor/shutdown.sock")
        message = json.loads(mock_sock.sendall.call_args[0][0].decode())
        assert message["version"] == "1.0"
        assert message["status"] == "nic-up"

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_up_alert_socket_error_is_not_delivered(self, mock_socket_class):
        """A connection failure is reported as not delivered."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")

        assert send_nic_up_alert("hypervisor/shutdown.sock") is False

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_alert_error_response_is_not_delivered(self, mock_socket_class, caplog):
        """An error reply (e.g. an older receiver that does not know nic-up) is retried."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "error", "message": "Unknown status"}'

        assert send_nic_up_alert("hypervisor/shutdown.sock") is False
        assert "Error from server: Unknown status" in caplog.text

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_alert_does_not_wait_longer_than_the_check_timeout(self, mock_socket_class):
        """A busy receiver must not hold the check until Consul kills it."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b'{"status": "success"}'

        send_nic_up_alert("hypervisor/shutdown.sock")

        mock_sock.settimeout.assert_called_once_with(3)

    @patch("tcp_health_check.socket.socket")
    @patch.dict("os.environ", {"SNAP_DATA": "/snap/data"})
    def test_send_nic_down_alert_returns_false_on_failure(self, mock_socket_class):
        """send_nic_down_alert reports delivery failure."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = socket.error("Connection refused")

        assert send_nic_down_alert("hypervisor/shutdown.sock") is False


class TestRecovery:
    """Test that nic-up is sent once after a delivered nic-down."""

    SERVERS = ["10.0.0.1:8301"]
    SOCKET = "hypervisor/shutdown.sock"

    @staticmethod
    def _reachable():
        conn = MagicMock()
        conn.__enter__ = MagicMock()
        conn.__exit__ = MagicMock()
        return conn

    @patch("tcp_health_check.send_nic_up_alert")
    @patch("tcp_health_check.send_nic_down_alert", return_value=True)
    @patch("tcp_health_check.socket.create_connection")
    def test_nic_up_sent_once_after_nic_down(self, mock_conn, mock_down, mock_up, tmp_path):
        """Failure -> nic-down; recovery -> nic-up exactly once; later checks send nothing."""
        mock_up.return_value = True
        state = str(tmp_path / "state.json")

        mock_conn.side_effect = socket.error("down")
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        mock_down.assert_called_once_with(self.SOCKET)
        assert read_state(state) == {"failure_count": 0, "alert_sent": True, "success_count": 0}

        mock_conn.side_effect = None
        mock_conn.return_value = self._reachable()
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        mock_up.assert_called_once_with(self.SOCKET)
        assert read_state(state) == {"failure_count": 0, "alert_sent": False, "success_count": 0}

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        mock_up.assert_called_once_with(self.SOCKET)

    @patch("tcp_health_check.send_nic_up_alert")
    @patch("tcp_health_check.socket.create_connection")
    def test_no_nic_up_without_prior_alert(self, mock_conn, mock_up, tmp_path):
        """A healthy node that never alerted never sends nic-up."""
        mock_conn.return_value = self._reachable()
        state = str(tmp_path / "state.json")

        tcp_check(self.SERVERS, self.SOCKET, state_file=state)

        mock_up.assert_not_called()

    @patch("tcp_health_check.send_nic_up_alert")
    @patch("tcp_health_check.send_nic_down_alert", return_value=True)
    @patch("tcp_health_check.socket.create_connection")
    def test_no_nic_up_below_failure_threshold(self, mock_conn, mock_down, mock_up, tmp_path):
        """Failures below the threshold send no alert, so recovery sends no nic-up."""
        state = str(tmp_path / "state.json")

        mock_conn.side_effect = socket.error("down")
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        mock_conn.side_effect = None
        mock_conn.return_value = self._reachable()
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)

        mock_down.assert_not_called()
        mock_up.assert_not_called()
        assert read_state(state) == {"failure_count": 0, "alert_sent": False, "success_count": 0}

    @patch("tcp_health_check.send_nic_up_alert")
    @patch("tcp_health_check.send_nic_down_alert", return_value=False)
    @patch("tcp_health_check.socket.create_connection")
    def test_undelivered_nic_down_does_not_arm_recovery(
        self, mock_conn, mock_down, mock_up, tmp_path
    ):
        """If nic-down could not be delivered there is nothing to undo."""
        state = str(tmp_path / "state.json")

        mock_conn.side_effect = socket.error("down")
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        mock_conn.side_effect = None
        mock_conn.return_value = self._reachable()
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)

        mock_up.assert_not_called()
        assert read_state(state)["alert_sent"] is False

    @patch("tcp_health_check.send_nic_up_alert", side_effect=[False, True])
    @patch("tcp_health_check.socket.create_connection")
    def test_failed_nic_up_is_retried(self, mock_conn, mock_up, tmp_path):
        """If nic-up cannot be delivered, the flag stays set and the next check retries."""
        state = str(tmp_path / "state.json")
        write_state(state, 0, True)
        mock_conn.return_value = self._reachable()

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        assert read_state(state)["alert_sent"] is True

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        assert read_state(state)["alert_sent"] is False
        assert mock_up.call_count == 2

    @patch("tcp_health_check.send_nic_up_alert")
    @patch("tcp_health_check.send_nic_down_alert", return_value=True)
    @patch("tcp_health_check.socket.create_connection")
    def test_repeated_outage_keeps_alert_flag(self, mock_conn, mock_down, mock_up, tmp_path):
        """A second nic-down during a continuing outage keeps the flag armed."""
        state = str(tmp_path / "state.json")
        mock_conn.side_effect = socket.error("down")

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=1, state_file=state)

        assert mock_down.call_count == 2
        mock_up.assert_not_called()
        assert read_state(state)["alert_sent"] is True

    def test_read_state_old_format_file(self, tmp_path):
        """A state file written before this change (no alert_sent) still loads."""
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"failure_count": 2}))

        assert read_state(str(state)) == {
            "failure_count": 2,
            "alert_sent": False,
            "success_count": 0,
        }


class TestRecoveryHysteresis:
    """nic-up needs the same run of consecutive successes that nic-down needs failures."""

    SERVERS = ["10.0.0.1:8301"]
    SOCKET = "hypervisor/shutdown.sock"

    @staticmethod
    def _reachable():
        conn = MagicMock()
        conn.__enter__ = MagicMock()
        conn.__exit__ = MagicMock()
        return conn

    @patch("tcp_health_check.send_nic_up_alert", return_value=True)
    @patch("tcp_health_check.socket.create_connection")
    def test_nic_up_waits_for_consecutive_successes(self, mock_conn, mock_up, tmp_path):
        state = str(tmp_path / "state.json")
        write_state(state, 0, True)
        mock_conn.return_value = self._reachable()

        for expected in (1, 2):
            tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
            mock_up.assert_not_called()
            assert read_state(state)["success_count"] == expected

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        mock_up.assert_called_once_with(self.SOCKET)
        assert read_state(state) == {"failure_count": 0, "alert_sent": False, "success_count": 0}

    @patch("tcp_health_check.send_nic_up_alert", return_value=True)
    @patch("tcp_health_check.socket.create_connection")
    def test_a_failure_restarts_the_run_of_successes(self, mock_conn, mock_up, tmp_path):
        """A flapping link does not send nic-up on every blip."""
        state = str(tmp_path / "state.json")
        write_state(state, 0, True)

        mock_conn.return_value = self._reachable()
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        mock_conn.side_effect = socket.error("down")
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        assert read_state(state)["success_count"] == 0
        assert read_state(state)["alert_sent"] is True

        mock_conn.side_effect = None
        mock_conn.return_value = self._reachable()
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        mock_up.assert_not_called()

    @patch("tcp_health_check.send_nic_up_alert", side_effect=[False, True])
    @patch("tcp_health_check.socket.create_connection")
    def test_failed_nic_up_is_retried_on_the_next_check(self, mock_conn, mock_up, tmp_path):
        state = str(tmp_path / "state.json")
        write_state(state, 0, True, success_count=2)
        mock_conn.return_value = self._reachable()

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        assert read_state(state)["alert_sent"] is True

        tcp_check(self.SERVERS, self.SOCKET, monitoring_samples=3, state_file=state)
        assert read_state(state)["alert_sent"] is False
        assert mock_up.call_count == 2


class TestStateFile:
    def test_write_is_atomic_and_leaves_no_temporary_file(self, tmp_path):
        state = tmp_path / "state.json"

        assert write_state(str(state), 2, True, 1) is True

        assert json.loads(state.read_text()) == {
            "failure_count": 2,
            "alert_sent": True,
            "success_count": 1,
        }
        assert [p.name for p in tmp_path.iterdir()] == ["state.json"]

    def test_failed_write_keeps_the_previous_state(self, tmp_path):
        state = tmp_path / "state.json"
        write_state(str(state), 0, True)

        with patch("tcp_health_check.json.dump", side_effect=OSError("disk full")):
            assert write_state(str(state), 1, False) is False

        assert read_state(str(state))["alert_sent"] is True
