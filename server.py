#!/usr/bin/env python3
"""DraygenDrop Server — run on WSL, reachable from Mac and Windows."""

import json
import socket
import threading
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file

# ── defaults ──────────────────────────────────────────────────────────────────
HTTP_PORT = 7474
UDP_PORT  = 7475
DROP_DIR  = Path.home() / "draygendrop"

app = Flask(__name__)
_drop_dir: Path = DROP_DIR


# ── helpers ───────────────────────────────────────────────────────────────────
def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n //= 1024


def _safe(filename: str) -> Path:
    """Resolve path and block directory traversal."""
    path = (_drop_dir / Path(filename).name).resolve()
    try:
        path.relative_to(_drop_dir.resolve())
    except ValueError:
        abort(403)
    return path


# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "no file field"}), 400
    results = []
    for f in request.files.getlist("file"):
        if not f.filename:
            continue
        dest = _drop_dir / f.filename
        f.save(dest)
        results.append({"filename": f.filename, "size": _fmt(dest.stat().st_size)})
    if not results:
        return jsonify({"error": "no files saved"}), 400
    if len(results) == 1:
        return jsonify({"success": True, **results[0]})
    return jsonify({"success": True, "files": results})


@app.route("/files")
def list_files():
    files = [
        {
            "name":  p.name,
            "size":  _fmt(p.stat().st_size),
            "bytes": p.stat().st_size,
            "mtime": int(p.stat().st_mtime),
        }
        for p in sorted(_drop_dir.iterdir())
        if p.is_file()
    ]
    return jsonify(files)


@app.route("/download/<path:filename>")
def download(filename):
    path = _safe(filename)
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/file/<path:filename>", methods=["DELETE"])
def delete(filename):
    path = _safe(filename)
    if not path.exists():
        return jsonify({"error": "not found"}), 404
    path.unlink()
    return jsonify({"success": True, "deleted": filename})


@app.route("/health")
def health():
    count = sum(1 for p in _drop_dir.iterdir() if p.is_file())
    return jsonify({"status": "ok", "files": count, "dir": str(_drop_dir)})


# ── UDP discovery ─────────────────────────────────────────────────────────────
def _discovery_listener(udp_port: int, http_port: int):
    """Respond to LAN discovery broadcasts from send clients."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", udp_port))
    ip = _local_ip()
    reply = f"DRAYGENDROP:{ip}:{http_port}".encode()
    while True:
        try:
            data, addr = sock.recvfrom(256)
            if data == b"DRAYGENDROP_DISCOVER":
                sock.sendto(reply, addr)
        except Exception:
            pass


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── entry point ───────────────────────────────────────────────────────────────
def main():
    import argparse

    p = argparse.ArgumentParser(description="DraygenDrop server")
    p.add_argument("--port", type=int, default=HTTP_PORT, metavar="PORT",
                   help=f"HTTP port (default: {HTTP_PORT})")
    p.add_argument("--dir",  type=Path, default=DROP_DIR,  metavar="PATH",
                   help="Drop directory (default: ~/draygendrop)")
    p.add_argument("--udp",  type=int, default=UDP_PORT,   metavar="PORT",
                   help=f"UDP discovery port (default: {UDP_PORT})")
    args = p.parse_args()

    global _drop_dir
    _drop_dir = args.dir.expanduser().resolve()
    _drop_dir.mkdir(parents=True, exist_ok=True)

    threading.Thread(
        target=_discovery_listener,
        args=(args.udp, args.port),
        daemon=True,
    ).start()

    ip = _local_ip()
    addr    = f"http://{ip}:{args.port}"
    dropdir = str(_drop_dir)
    udpline = f"UDP :{args.udp}"
    W = max(len(addr), len(dropdir), len(udpline), 36) + 16
    print(f"\n  ┌{'─' * W}┐")
    print(f"  │{'  DraygenDrop Server':^{W}}│")
    print(f"  ├{'─' * W}┤")
    print(f"  │  {'Address':<10}  {addr:<{W - 14}}│")
    print(f"  │  {'Drop dir':<10}  {dropdir:<{W - 14}}│")
    print(f"  │  {'Discovery':<10}  {udpline:<{W - 14}}│")
    print(f"  └{'─' * W}┘")
    print(f"\n  Ctrl+C to stop\n")

    app.run(host="0.0.0.0", port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
