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


def send_nic_down_alert(socket_path):
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


def tcp_check(servers, socket_path):
    """Perform a TCP health check on a list of servers.

    Args:
        servers: List of servers to check in format "host:port"
        socket_path: Path to the Unix socket.
    """
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

    if nic_down:
        if socket_path:
            send_nic_down_alert(socket_path)
        else:
            logging.error("Cannot send alert: socket_path is required but was not provided")
    else:
        logging.info("✅ All servers reachable. No alert triggered.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP health check for Consul servers")
    parser.add_argument("servers", nargs="+", help="List of servers to check in format host:port")
    parser.add_argument("--socket-path", "-s", help="Path to the Unix socket")

    args = parser.parse_args()

    if not args.servers:
        logging.error(
            "Usage: python3 tcp_health_check.py <IP:PORT> [<IP:PORT>...] [--socket-path PATH]"
        )
        sys.exit(1)

    tcp_check(args.servers, args.socket_path)
