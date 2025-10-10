#!/usr/bin/env python3
"""Bridge STDIO-based Model Context clients to the x96dbg MCP TCP server."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
from typing import Optional


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bridge STDIO JSON-RPC traffic to the x96dbg MCP TCP server",
    )
    parser.add_argument("--host", default="127.0.0.1", help="MCP server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=51337, help="MCP server port (default: 51337)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket connect timeout in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def stdin_to_socket(sock: socket.socket, stop_event: threading.Event) -> None:
    try:
        while not stop_event.is_set():
            line = sys.stdin.buffer.readline()
            if not line:
                logging.debug("STDIN closed; shutting down socket writer")
                break
            logging.debug("-> TCP %r", line)
            sock.sendall(line)
    except Exception as exc:
        logging.exception("stdin->socket thread failed: %s", exc)
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        stop_event.set()


def socket_to_stdout(sock: socket.socket, stop_event: threading.Event) -> None:
    sock_file = sock.makefile("rb", buffering=0)
    try:
        while not stop_event.is_set():
            try:
                line = sock_file.readline()
            except TimeoutError:
                continue
            if not line:
                logging.debug("TCP stream closed; stopping reader")
                break
            logging.debug("<- TCP %r", line)
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
    except Exception as exc:
        logging.exception("socket->stdout thread failed: %s", exc)
    finally:
        stop_event.set()
        sock_file.close()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    try:
        sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
        sock.settimeout(None)
    except OSError as exc:
        logging.error("Failed to connect to %s:%s (%s)", args.host, args.port, exc)
        return 1

    logging.info("Connected to MCP server at %s:%s", args.host, args.port)

    stop_event = threading.Event()
    threads = [
        threading.Thread(target=stdin_to_socket, args=(sock, stop_event), name="stdin->socket"),
        threading.Thread(target=socket_to_stdout, args=(sock, stop_event), name="socket->stdout"),
    ]

    for thread in threads:
        thread.start()

    try:
        while not stop_event.is_set():
            for thread in threads:
                thread.join(timeout=0.1)
            if all(not thread.is_alive() for thread in threads):
                break
    except KeyboardInterrupt:
        logging.info("Interrupted; shutting down bridge")
        stop_event.set()

    sock.close()
    logging.info("Bridge terminated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
