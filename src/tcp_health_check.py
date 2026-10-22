"""Health check functions for monitoring TCP servers and sending alert when required."""

import argparse
import enum
import json
import logging
import os
import socket
import sys
import time
from logging.handlers import TimedRotatingFileHandler

PROTOCOL_VERSION = "1.0"
# Consul kills a check after its timeout, so never wait on the receiver for longer than this.
SOCKET_TIMEOUT = 3


class NetworkStatus(enum.Enum):
    """Enum for network interface status."""

    NIC_DOWN = "nic-down"
    NIC_UP = "nic-up"


def read_state(state_file: str) -> dict:
    """Read the persisted health check state.

    Args:
        state_file: Path to the state file.

    Returns:
        dict: ``{"failure_count": int, "alert_sent": bool, "success_count": int}``.
        Missing or unreadable files give the defaults (no failures, no alert sent).
    """
    state = {"failure_count": 0, "alert_sent": False, "success_count": 0}
    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                state_data = json.load(f)
                state["failure_count"] = state_data.get("failure_count", 0)
                state["alert_sent"] = bool(state_data.get("alert_sent", False))
                state["success_count"] = state_data.get("success_count", 0)
    except Exception as e:
        logging.warning(f"Failed to read state file: {e}")
    return state


def write_state(
    state_file: str, failure_count: int, alert_sent: bool, success_count: int = 0
) -> bool:
    """Write the health check state.

    The file is replaced atomically: Consul kills a check that overruns its timeout, and a
    half-written file would lose ``alert_sent`` and with it the nic-up.

    Args:
        state_file: Path to the state file.
        failure_count: The failure count to write.
        alert_sent: Whether a nic-down alert was delivered and not yet cleared by nic-up.
        success_count: Consecutive successful checks since the nic-down was delivered.

    Returns:
        bool: True if write was successful, False otherwise.
    """
    tmp_file = f"{state_file}.tmp"
    try:
        with open(tmp_file, "w") as f:
            json.dump(
                {
                    "failure_count": failure_count,
                    "alert_sent": alert_sent,
                    "success_count": success_count,
                },
                f,
            )
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, state_file)
        return True
    except Exception as e:
        logging.warning(f"Failed to write state file: {e}")
        return False


def read_failure_count(state_file: str) -> int:
    """Read failure count from state file.

    Args:
        state_file: Path to the state file.

    Returns:
        int: The failure count, or 0 if file doesn't exist or can't be read.
    """
    return read_state(state_file)["failure_count"]


def write_failure_count(state_file: str, failure_count: int) -> bool:
    """Write failure count to state file, keeping the rest of the state.

    Args:
        state_file: Path to the state file.
        failure_count: The failure count to write.

    Returns:
        bool: True if write was successful, False otherwise.
    """
    state = read_state(state_file)
    return write_state(state_file, failure_count, state["alert_sent"], state["success_count"])


def _send_status(socket_path: str, status: NetworkStatus) -> bool:
    """Send a network status message through the Unix socket.

    Args:
        socket_path: Path to the Unix socket, relative to SNAP_DATA.
        status: The network status to report.

    Returns:
        bool: True if the receiver accepted the message. False if it could not be
        delivered or the receiver answered with an error (for example an older receiver
        that does not know nic-up), so that the caller can try again later.
    """
    socket_path = os.path.join(os.environ["SNAP_DATA"], socket_path)
    logging.info(f"Sending {status.value} signal via Unix socket at {socket_path}...")
    try:
        message = {
            "version": PROTOCOL_VERSION,
            "timestamp": time.time(),
            "status": status.value,
        }

        json_message = json.dumps(message)
        logging.debug(f"Sending message: {json_message}")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect(socket_path)
            sock.sendall(json_message.encode())

            response = sock.recv(1024).decode().strip()
            logging.info(f"Response: {response}")

            response_data = json.loads(response)
            if response_data.get("status") == "error":
                logging.error(f"Error from server: {response_data.get('message')}")
                return False
        return True
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Error sending alert signal: {e}")
    return False


def send_nic_down_alert(socket_path: str) -> bool:
    """Send nic down signal through Unix socket.

    Args:
        socket_path: Path to the Unix socket.

    Returns:
        bool: True if the signal was delivered, False otherwise.
    """
    return _send_status(socket_path, NetworkStatus.NIC_DOWN)


def send_nic_up_alert(socket_path: str) -> bool:
    """Send nic up (recovered) signal through Unix socket.

    Args:
        socket_path: Path to the Unix socket.

    Returns:
        bool: True if the signal was delivered, False otherwise.
    """
    return _send_status(socket_path, NetworkStatus.NIC_UP)


def _any_server_unreachable(servers: list[str]) -> bool:
    """Return True if a TCP connection to any of the servers fails."""
    unreachable = False
    for server in servers:
        host, port = server.split(":")
        port = int(port)

        try:
            with socket.create_connection((host, port), timeout=2):
                logging.info(f"Network is reachable on {server}")
        except (socket.timeout, socket.error) as e:
            logging.warning(f"Network is not reachable on {server}: {e}")
            unreachable = True
    return unreachable


def _on_failure(state: dict, socket_path: str | None, monitoring_samples: int) -> dict:
    """Update the failure count and send nic-down once the threshold is reached.

    Returns:
        dict: The new state. A failed check also ends any run of successful ones.
    """
    failure_count = state["failure_count"] + 1
    alert_sent = state["alert_sent"]
    logging.info(f"Health check failed. Failure count: {failure_count}/{monitoring_samples}")

    if failure_count < monitoring_samples:
        logging.info(f"Failure threshold not reached yet ({failure_count}/{monitoring_samples})")
    elif not socket_path:
        logging.error("Cannot send alert: socket_path is required but was not provided")
    else:
        if send_nic_down_alert(socket_path):
            # Remember the alert so a nic-up is sent once the network recovers
            alert_sent = True
        # Reset counter after sending alert
        failure_count = 0

    return {"failure_count": failure_count, "alert_sent": alert_sent, "success_count": 0}


def _on_success(state: dict, socket_path: str | None, monitoring_samples: int) -> dict:
    """Reset the failure count and send nic-up once the network has stayed up.

    The nic-up is only sent after ``monitoring_samples`` consecutive successful checks,
    like the nic-down needs consecutive failures, so that a flapping link does not
    restart nova-compute on every blip. If the nic-up cannot be delivered the flag is
    kept, so the next check retries.

    Returns:
        dict: The new state.
    """
    alert_sent = state["alert_sent"]
    success_count = state["success_count"]
    if state["failure_count"] > 0:
        logging.info("Network is reachable. Resetting failure count.")

    if alert_sent:
        success_count += 1
        logging.info(f"Network recovered. Success count: {success_count}/{monitoring_samples}")
        if success_count >= monitoring_samples and socket_path:
            if send_nic_up_alert(socket_path):
                alert_sent = False
                success_count = 0
    else:
        success_count = 0

    return {"failure_count": 0, "alert_sent": alert_sent, "success_count": success_count}


def tcp_check(
    servers: list[str],
    socket_path: str | None,
    monitoring_samples: int = 3,
    state_file: str | None = None,
) -> None:
    """Perform a TCP health check on a list of servers.

    Sends nic-down after ``monitoring_samples`` consecutive failed checks, and a single
    nic-up after ``monitoring_samples`` consecutive successful checks that follow a
    delivered nic-down.

    Args:
        servers: List of servers to check in format "host:port"
        socket_path: Path to the Unix socket.
        monitoring_samples: Number of consecutive failures (or, after an alert,
            successes) before signalling the receiver.
        state_file: Path to file storing failure count state. If None, uses SNAP_DATA/tcp_health_check_state.json
    """
    # Use snap data directory for state file if not specified
    if state_file is None:
        snap_data = os.environ.get("SNAP_DATA", "/tmp")
        state_file = os.path.join(snap_data, "tcp_health_check_state.json")

    state = read_state(state_file)

    if _any_server_unreachable(servers):
        new_state = _on_failure(state, socket_path, monitoring_samples)
    else:
        new_state = _on_success(state, socket_path, monitoring_samples)

    if new_state != state:
        write_state(state_file, **new_state)


def _configure_logging():
    """Configure logging so output is visible when Consul runs this script as a subprocess."""
    fmt = "%(asctime)s %(levelname)s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt=datefmt)
    logging.basicConfig(
        level=logging.DEBUG, format=fmt, datefmt=datefmt, stream=sys.stderr, force=True
    )
    snap_data = os.environ.get("SNAP_DATA")
    if snap_data:
        log_path = os.path.join(snap_data, "tcp_health_check.log")
        handler = TimedRotatingFileHandler(
            log_path, when="midnight", backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)


if __name__ == "__main__":
    _configure_logging()

    parser = argparse.ArgumentParser(description="TCP health check for Consul servers")
    parser.add_argument("servers", nargs="+", help="List of servers to check in format host:port")
    parser.add_argument("--socket-path", "-s", help="Path to the Unix socket")
    parser.add_argument(
        "--monitoring-samples",
        "-m",
        type=int,
        default=3,
        help="Number of consecutive failures before sending alert",
    )

    args = parser.parse_args()

    if not args.servers:
        logging.error(
            "Usage: python3 tcp_health_check.py <IP:PORT> [<IP:PORT>...] [--socket-path PATH] [--monitoring-samples N]"
        )
        sys.exit(1)

    tcp_check(args.servers, args.socket_path, args.monitoring_samples)
