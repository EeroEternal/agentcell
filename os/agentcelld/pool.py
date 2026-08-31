#!/usr/bin/env python3
"""
Pre-warm N `sand serve` cells and dispatch execs into them.

This is the process-model piece of AgentCell OS that already runs on a
normal distro: clone/mount/seccomp happen at pool start, not per command.

    python3 os/agentcelld/pool.py --size 4          # foreground pool
    python3 os/agentcelld/pool.py exec -- echo hi   # another terminal
    python3 os/agentcelld/pool.py status
    python3 os/agentcelld/pool.py stop

Control socket: $XDG_RUNTIME_DIR/agentcelld.sock (or /tmp).
"""
from __future__ import annotations

import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SAND = os.path.join(ROOT, "sand")
RT = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
CTL = os.path.join(RT, "agentcelld.sock")
SOCK_RE = re.compile(rb"serving (\S*agentcell-\d+\.sock)")


def _wait_sock(proc, timeout=5):
    buf, deadline = b"", time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([proc.stderr], [], [], 0.2)
        if r:
            chunk = os.read(proc.stderr.fileno(), 4096)
            if not chunk:
                break
            buf += chunk
        m = SOCK_RE.search(buf)
        if m:
            return m.group(1).decode()
        if proc.poll() is not None:
            break
    return None


def _exec(sock, argv, stdin=b"", timeout=30):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock)
    hdr = struct.pack("<I", len(argv))
    for a in argv:
        a = a.encode() if isinstance(a, str) else a
        hdr += struct.pack("<I", len(a)) + a
    s.sendall(hdr)
    if stdin:
        s.sendall(stdin)
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    if len(data) < 4:
        raise RuntimeError("short reply")
    return data[:-4], struct.unpack("<I", data[-4:])[0]


class Pool:
    def __init__(self, size, extra_args):
        self.size = size
        self.extra = extra_args
        self.cells = []
        self.rr = 0
        self.lock = threading.Lock()

    def start(self):
        for i in range(self.size):
            p = subprocess.Popen(
                [SAND, "serve", *self.extra],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            sock = _wait_sock(p)
            if not sock:
                p.kill()
                raise RuntimeError(f"cell {i} failed to start")
            self.cells.append({"proc": p, "sock": sock, "execs": 0})
            print(f"pool: cell {i} {sock}", flush=True)

    def pick(self):
        with self.lock:
            c = self.cells[self.rr % len(self.cells)]
            self.rr += 1
            c["execs"] += 1
            return c

    def stop(self):
        for c in self.cells:
            c["proc"].terminate()
            try:
                c["proc"].wait(timeout=3)
            except subprocess.TimeoutExpired:
                c["proc"].kill()
        self.cells.clear()


def cmd_serve(size, extra):
    if os.path.exists(CTL):
        os.unlink(CTL)
    pool = Pool(size, extra)
    pool.start()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(CTL)
    srv.listen(16)
    print(f"pool: listening {CTL}  size={size}", flush=True)

    def handle(conn):
        try:
            raw = b""
            while b"\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
            line = raw.split(b"\n", 1)[0].decode()
            parts = line.split(" ", 1)
            op = parts[0]
            if op == "STATUS":
                st = [{"sock": c["sock"], "execs": c["execs"]} for c in pool.cells]
                conn.sendall((json.dumps(st) + "\n").encode())
            elif op == "EXEC":
                argv = json.loads(parts[1])
                c = pool.pick()
                out, code = _exec(c["sock"], argv)
                conn.sendall(json.dumps({"stdout": out.decode("utf-8", "replace"),
                                         "code": code}).encode() + b"\n")
            elif op == "STOP":
                conn.sendall(b"OK\n")
                conn.close()
                pool.stop()
                os._exit(0)
            else:
                conn.sendall(b'{"error":"unknown"}\n')
        except Exception as e:
            try:
                conn.sendall((json.dumps({"error": str(e)}) + "\n").encode())
            except OSError:
                pass
        finally:
            conn.close()

    try:
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        pool.stop()
        try:
            os.unlink(CTL)
        except OSError:
            pass


def _rpc(line: str) -> dict | list:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(CTL)
    s.sendall(line.encode() + b"\n")
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode())


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "exec":
        argv = args[2:] if args[1:2] == ["--"] else args[1:]
        if not argv:
            print("usage: pool.py exec -- CMD ...", file=sys.stderr)
            return 2
        r = _rpc("EXEC " + json.dumps(argv))
        sys.stdout.write(r.get("stdout") or r.get("error", "") + "\n")
        return int(r.get("code") or (1 if "error" in r else 0))
    if args[0] == "status":
        print(json.dumps(_rpc("STATUS"), indent=2))
        return 0
    if args[0] == "stop":
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(CTL)
            s.sendall(b"STOP\n")
            s.close()
        except OSError:
            pass
        return 0

    size = 2
    extra = []
    i = 0
    while i < len(args):
        if args[i] == "--size" and i + 1 < len(args):
            size = int(args[i + 1]); i += 2
        elif args[i] == "--":
            extra = args[i + 1:]; break
        else:
            extra.append(args[i]); i += 1
    default_root = os.path.join(ROOT, "os", "out", "cell-root")
    if os.path.isdir(default_root) and "--rootfs" not in extra:
        extra = ["--rootfs", default_root, *extra]
        print(f"pool: using --rootfs {default_root}", flush=True)
    cmd_serve(size, extra)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
