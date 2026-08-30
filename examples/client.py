#!/usr/bin/env python3
"""
How to talk to an AgentCell sandbox from Python — no dependencies.

One file, three patterns:

  1. batch        run a command, get its COMPLETE output + exact exit code
  2. streaming    feed stdin chunk by chunk (e.g. as agent input arrives),
                  still read the complete response at the end
  3. interactive  keep an agent process alive in the cell and chat
                  turn by turn (application-level sentinel framing)

Protocol (serve mode, one unix socket per cell):

  request : u32 argc { u32 len, bytes }*argc        (little endian)
            ...then the socket is full-duplex: every byte you write is
            the command's stdin, LIVE; shutdown(SHUT_WR) means stdin EOF
  response: the command's stdout+stderr bytes, then u32 exit status,
            then EOF (server closes)

So "read the COMPLETE response" = read until EOF; the last 4 bytes are
the exit status, everything before them is the output.

Run the demo at the bottom:  python3 examples/client.py
"""
import os
import re
import select
import socket
import struct
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SAND = os.path.join(HERE, "..", "sand")

_SOCK_RE = re.compile(rb"serving (\S*agentcell-\d+\.sock)")


class Cell:
    """One long-lived sandbox (sand serve).  One Cell per session; not
    thread-safe — create one per thread if you need concurrency."""

    def __init__(self, *serve_args):
        # every isolation layer applies to everything we ever exec here
        self.proc = subprocess.Popen(
            [SAND, "serve", *serve_args],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # the "serving <sock>" line lands once the jail is fully set up
        buf, deadline = b"", time.time() + 5
        while time.time() < deadline:
            r, _, _ = select.select([self.proc.stderr], [], [], 0.2)
            if r:
                chunk = os.read(self.proc.stderr.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
            m = _SOCK_RE.search(buf)
            if m:
                self.sock = m.group(1).decode()
                return
            if self.proc.poll() is not None:
                break
        self.proc.kill()
        raise RuntimeError("cell failed to start")

    def _connect(self, argv):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock)
        hdr = struct.pack("<I", len(argv))
        for a in argv:
            a = a.encode() if isinstance(a, str) else a
            hdr += struct.pack("<I", len(a)) + a
        s.sendall(hdr)
        return s

    def run(self, *argv, stdin=b"", timeout=30):
        """Pattern 1+2: batch or streamed stdin; always returns the
        COMPLETE response: (output_bytes, exit_code).

        stdin: bytes            — sent at once
               iterable[bytes]  — streamed chunk by chunk while the
                                  command is already running
        """
        deadline = time.time() + timeout
        s = self._connect(argv)
        chunks = iter([stdin]) if isinstance(stdin, bytes) else iter(stdin)
        pending = None            # one chunk at a time is in flight
        reply = bytearray()

        def feed():
            nonlocal pending
            if pending is None:
                pending = next(chunks, None)
            if pending is None:
                s.shutdown(socket.SHUT_WR)      # stdin EOF for the jail
                return False
            s.sendall(pending)
            pending = None
            return True

        writable = True
        try:
            while True:
                if time.time() > deadline:
                    raise TimeoutError(argv)
                wfds = [s] if writable else []
                r, w, _ = select.select([s], wfds, [], 0.2)
                if w:
                    writable = feed()
                if r:
                    data = s.recv(65536)
                    if not data:
                        break                   # EOF: response complete
                    reply += data
        finally:
            s.close()
        if len(reply) < 4:
            raise RuntimeError("short reply from cell")
        # last 4 bytes = exit status; everything before = the output
        return bytes(reply[:-4]), struct.unpack("<I", reply[-4:])[0]

    def session(self, *argv):
        """Pattern 3: a long-lived process in the cell you can talk to
        turn by turn.  Yields a Session; see demo below."""
        return Session(self._connect(argv))

    def close(self):
        self.proc.terminate()           # serve mode: full cell cleanup
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    __enter__ = lambda self: self
    __exit__ = lambda self, *a: self.close()


class Session:
    """A live process inside the cell.  stdin stays open; you frame
    turns yourself (here: read until a sentinel line)."""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""

    def send(self, data: bytes):
        self.s.sendall(data)

    def read_until(self, sentinel: bytes, timeout=10) -> bytes:
        """Read until `sentinel` arrives — one COMPLETE agent turn."""
        deadline = time.time() + timeout
        while sentinel not in self.buf:
            if time.time() > deadline:
                raise TimeoutError("turn never completed")
            r, _, _ = select.select([self.s], [], [], 0.2)
            if r:
                data = self.s.recv(65536)
                if not data:
                    break
                self.buf += data
        line, _, self.buf = self.buf.partition(sentinel)
        return line + (sentinel if _ else b"")

    def close(self):
        self.s.shutdown(socket.SHUT_WR)     # stdin EOF ends the process
        self.s.close()


# ---------------------------------------------------------------------------
# demo: a tiny "agent" that lives in the cell and answers in JSON lines
# ---------------------------------------------------------------------------
AGENT = r"""
import sys, json
print('{"ready": true}', flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    ans = {"echo": req["msg"].upper(), "cell": True, "turn": req.get("turn")}
    print(json.dumps(ans), flush=True)
    print("===END===", flush=True)      # turn sentinel
""".strip()

if __name__ == "__main__":
    with Cell() as cell:
        print("cell up:", cell.sock)

        # 1) batch: complete output + exact exit code
        out, code = cell.run("sh", "-c", "echo hello; pwd; exit 3")
        print("1) batch      ->", out.decode().split(), "exit", code)

        # 2) streamed stdin (chunks over time), complete response at EOF
        def feed():
            for i in range(3):
                time.sleep(0.2)
                yield f"line{i}\n".encode()
        out, code = cell.run("cat", stdin=feed())
        print("2) streamed   ->", out.decode().split(), "exit", code)

        # 3) interactive agent: send a turn, read until the sentinel —
        #    that's one COMPLETE agent response, repeat as long as you like
        agent = cell.session("python3", "-c", AGENT)
        print("3) agent boot ->", agent.read_until(b"\n").decode().strip())
        for turn in (1, 2):
            agent.send(b'{"msg":"hello from python","turn":%d}\n' % turn)
            resp = agent.read_until(b"===END===\n")
            print(f"   turn {turn}   ->", resp.decode().split("\n")[0])
        agent.close()
    print("cell torn down (socket, cgroup, jail — all cleaned)")
