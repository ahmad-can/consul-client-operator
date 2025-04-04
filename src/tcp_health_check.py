"""Health check functions for monitoring TCP servers and signaling shutdown."""

import logging
import os
import socket
import sys

SOCKET_PATH = os.path.join(os.environ["SNAP_DATA"], "data", "shutdown.sock")


def send_shutdown_to_hypervisor():
    """Send shutdown signal to the hypervisor through Unix socket."""
    logging.info("Sending shutdown signal to hypervisor via Unix socket...")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(SOCKET_PATH)
            sock.sendall(b"shutdown\n")
            response = sock.recv(1024).decode().strip()
            logging.info(f"Response: {response}")
    except socket.error as e:
        logging.error(f"Socket error: {e}")


def tcp_check(servers):
    """Perform a TCP health check on a list of servers."""
    shutdown_required = False

    for server in servers:
        host, port = server.split(":")
        port = int(port)

        try:
            with socket.create_connection((host, port), timeout=5):
                logging.info(f"TCP check successful for {server}")
        except (socket.timeout, socket.error) as e:
            logging.warning(f"TCP check failed for {server}: {e}")
            shutdown_required = True

    if shutdown_required:
        send_shutdown_to_hypervisor()
    else:
        logging.info("✅ All servers reachable. No shutdown triggered.")


if __name__ == "__main__":
    servers = sys.argv[1:]
    if not servers:
        logging.error("Usage: python3 tcp_monitor.py <IP:PORT> [<IP:PORT>...]")
        sys.exit(1)

    tcp_check(servers)
