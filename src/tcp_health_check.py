"""Health check functions for monitoring TCP servers and sending alert when required."""

import argparse
import enum
import json
import logging
import os
import socket
import sys
import time

PROTOCOL_VERSION = "1.0"


class NetworkStatus(enum.Enum):
    """Enum for network interface status."""

    NIC_DOWN = "nic-down"


def read_failure_count(state_file: str) -> int:
    """Read failure count from state file.

    Args:
        state_file: Path to the state file.

    Returns:
        int: The failure count, or 0 if file doesn't exist or can't be read.
    """
    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                state_data = json.load(f)
                return state_data.get("failure_count", 0)
    except Exception as e:
        logging.warning(f"Failed to read state file: {e}")
    return 0


def write_failure_count(state_file: str, failure_count: int) -> bool:
    """Write failure count to state file.

    Args:
        state_file: Path to the state file.
        failure_count: The failure count to write.

    Returns:
        bool: True if write was successful, False otherwise.
    """
    try:
        with open(state_file, "w") as f:
            json.dump({"failure_count": failure_count}, f)
        return True
    except Exception as e:
        logging.warning(f"Failed to write state file: {e}")
        return False


def send_nic_down_alert(socket_path: str) -> None:
    """Send nic down signal through Unix socket.

    Args:
        socket_path: Path to the Unix socket.
    """
    socket_path = os.path.join(os.environ["SNAP_DATA"], socket_path)
    logging.info(f"Sending nic down alert signal via Unix socket at {socket_path}...")
    try:
        message = {
            "version": PROTOCOL_VERSION,
            "timestamp": time.time(),
            "status": NetworkStatus.NIC_DOWN.value,
        }

        json_message = json.dumps(message)
        logging.debug(f"Sending message: {json_message}")

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(socket_path)
            sock.sendall(json_message.encode())

            response = sock.recv(1024).decode().strip()
            logging.info(f"Response: {response}")

            response_data = json.loads(response)
            if response_data.get("status") == "error":
                logging.error(f"Error from server: {response_data.get('message')}")

    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"Error sending alert signal: {e}")


def tcp_check(
    servers: list[str],
    socket_path: str | None,
    monitoring_samples: int = 3,
    state_file: str | None = None,
) -> None:
    """Perform a TCP health check on a list of servers.

    Args:
        servers: List of servers to check in format "host:port"
        socket_path: Path to the Unix socket.
        monitoring_samples: Number of consecutive failures before sending alert.
        state_file: Path to file storing failure count state. If None, uses SNAP_DATA/tcp_health_check_state.json
    """
    # Use snap data directory for state file if not specified
    if state_file is None:
        snap_data = os.environ.get("SNAP_DATA", "/tmp")
        state_file = os.path.join(snap_data, "tcp_health_check_state.json")

    nic_down = False

    for server in servers:
        host, port = server.split(":")
        port = int(port)

        try:
            with socket.create_connection((host, port), timeout=5):
                logging.info(f"TCP check successful for {server}")
        except (socket.timeout, socket.error) as e:
            logging.warning(f"TCP check failed for {server}: {e}")
            nic_down = True

    # Load current failure count from state file
    failure_count = read_failure_count(state_file)

    if nic_down:
        failure_count += 1
        logging.info(f"Health check failed. Failure count: {failure_count}/{monitoring_samples}")

        # Save updated failure count
        write_failure_count(state_file, failure_count)

        # Only send alert if we've reached the threshold
        if failure_count >= monitoring_samples:
            if socket_path:
                send_nic_down_alert(socket_path)
                # Reset counter after sending alert
                write_failure_count(state_file, 0)
            else:
                logging.error("Cannot send alert: socket_path is required but was not provided")
        else:
            logging.info(
                f"Failure threshold not reached yet ({failure_count}/{monitoring_samples})"
            )
    else:
        # Reset failure count on success
        if failure_count > 0:
            logging.info("✅ All servers reachable. Resetting failure count.")
            write_failure_count(state_file, 0)
        else:
            logging.info("✅ All servers reachable. No alert triggered.")


if __name__ == "__main__":
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
