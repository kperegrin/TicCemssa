#!/usr/bin/env python
"""
Client de prova ICAP per al nostre inspector.

Us:
    python icap_test_client.py non_sensitive_test_document.pdf
    python icap_test_client.py fake_sensitive_test_data.pdf

Per defecte connecta amb:
    icap://127.0.0.1:1345/scan
"""

from __future__ import annotations

import argparse
import mimetypes
import socket
from pathlib import Path


def recv_all(sock: socket.socket) -> bytes:
    """Llegeix tota la resposta fins que el servidor tanca o expira el timeout."""

    chunks: list[bytes] = []
    sock.settimeout(5)
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def icap_options(host: str, port: int, service: str) -> bytes:
    """Envia OPTIONS per comprovar que el servei ICAP respon."""

    request = (
        f"OPTIONS icap://{host}:{port}/{service} ICAP/1.0\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    ).encode("latin-1")

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        return recv_all(sock)


def icap_reqmod(host: str, port: int, service: str, file_path: Path) -> bytes:
    """Envia un fitxer com si fos un upload HTTP encapsulat dins REQMOD."""

    body = file_path.read_bytes()
    content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    chunked_body = f"{len(body):X}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"

    http_headers = (
        f"POST /upload HTTP/1.1\r\n"
        f"Host: example.local\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{file_path.name}\"\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("latin-1")

    icap_headers = (
        f"REQMOD icap://{host}:{port}/{service} ICAP/1.0\r\n"
        f"Host: {host}\r\n"
        f"Allow: 204\r\n"
        f"Encapsulated: req-hdr=0, req-body={len(http_headers)}\r\n"
        "\r\n"
    ).encode("latin-1")

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(icap_headers + http_headers + chunked_body)
        sock.shutdown(socket.SHUT_WR)
        return recv_all(sock)


def first_line(response: bytes) -> str:
    """Retorna la primera linia de la resposta ICAP."""

    return response.decode("latin-1", errors="replace").splitlines()[0] if response else "(sense resposta)"


def main() -> int:
    parser = argparse.ArgumentParser(description="Client de prova ICAP per inspector.py")
    parser.add_argument("file", help="Fitxer a enviar al servidor ICAP")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1345)
    parser.add_argument("--service", default="scan")
    parser.add_argument("--skip-options", action="store_true")
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"ERROR: no trobat: {file_path}")
        return 2

    if not args.skip_options:
        options_response = icap_options(args.host, args.port, args.service)
        print("OPTIONS:", first_line(options_response))

    response = icap_reqmod(args.host, args.port, args.service, file_path)
    status = first_line(response)
    print("REQMOD: ", status)

    text = response.decode("latin-1", errors="replace")
    if "403" in text:
        print("RESULTAT: bloquejat")
        return 1
    if "200" in status or "204" in status:
        print("RESULTAT: permes")
        return 0

    print("RESULTAT: resposta no reconeguda")
    print(text[:1000])
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
