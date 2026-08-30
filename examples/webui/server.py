#!/usr/bin/env python3
"""
agentcell web gateway — a demo backend service for driving sand cells
from a web UI.  Single file, Python stdlib only.

    python3 examples/webui/server.py [PORT]        # default 8080
    open http://127.0.0.1:8080

Architecture:

    browser (this page)  <--HTTP-->  gateway (unprivileged!)  <--unix sock-->  cells
                                       |
                                       +-- sand serve   (one cell per session)
                                       +-- sand exec    (one request per command)

API:
  POST   /api/cells                          -> {id, sock}
  GET    /api/cells                          -> [{id, sock, uptime, execs}]
  POST   /api/cells/<id>/exec  {"cmd": ".."} -> {stdout, code}
  DELETE /api/cells/<id>                     -> {}

The gateway needs NO root: sand's isolation is all unprivileged.
Add --secure / --net veth to SERVE_FLAGS once `sudo agentlsm serve`
is running for kernel-level policy + NAT networking.

DEMO ONLY: no authentication — bind to 127.0.0.1 and put your own
authn/authz in front (reverse proxy, session middleware, ...).
"""
import json
import os
import re
import select
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SAND = os.path.join(HERE, "..", "..", "sand")
PORT = 8080
# extra isolation/policy flags every cell gets, e.g. ["--secure"]:
SERVE_FLAGS = []

SOCK_RE = re.compile(rb"serving (\S*agentcell-(\d+)\.sock)")

cells = {}               # id -> {proc, sock, started, execs}
lock = threading.Lock()


def cell_create():
    """sand serve: build the jail once, keep it alive, print its socket."""
    p = subprocess.Popen([SAND, "serve", *SERVE_FLAGS],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    buf, deadline = b"", time.time() + 5
    while time.time() < deadline:
        r, _, _ = select.select([p.stderr], [], [], 0.2)
        if r:
            chunk = os.read(p.stderr.fileno(), 4096)
            if not chunk:
                break
            buf += chunk
        m = SOCK_RE.search(buf)
        if m:
            sock, cid = m.group(1).decode(), m.group(2).decode()
            with lock:
                cells[cid] = {"proc": p, "sock": sock,
                              "started": time.time(), "execs": 0}
            return cid, sock
        if p.poll() is not None:
            break
    p.kill()
    raise RuntimeError("cell failed to start")


def cell_exec(cid, cmd, timeout=30):
    with lock:
        c = cells.get(cid)
    if not c:
        raise KeyError(cid)
    # sand exec: stdin via memfd, stdout+stderr stream back, exit code exact
    r = subprocess.run([SAND, "exec", c["sock"], "--", "bash", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    with lock:
        c["execs"] += 1
    out = r.stdout + (r.stderr if r.returncode == 2 else "")
    return out, r.returncode


def cell_delete(cid):
    with lock:
        c = cells.pop(cid, None)
    if not c:
        return
    c["proc"].terminate()          # serve mode handles SIGTERM: full cleanup
    try:
        c["proc"].wait(timeout=3)
    except subprocess.TimeoutExpired:
        c["proc"].kill()


PAGE = """<!doctype html>
<meta charset="utf-8"><title>agentcell console</title>
<style>
  body{background:#111;color:#ddd;font:14px/1.4 monospace;margin:0;padding:16px}
  #out{white-space:pre-wrap;background:#000;border:1px solid #333;
       padding:12px;height:60vh;overflow-y:auto;border-radius:6px}
  #cmd{width:100%;background:#111;border:0;border-top:1px solid #333;
       color:#0f0;font:inherit;padding:10px;outline:none}
  .meta{color:#888} .err{color:#f66}
</style>
<h3>agentcell &mdash; web console <span class=meta id=meta>(starting cell...)</span></h3>
<div id="out"></div>
<input id="cmd" placeholder="command runs INSIDE the sandbox — try: ls /  ·  cat /etc/shadow  ·  mount" autofocus>
<script>
const out = document.getElementById("out"), cmd = document.getElementById("cmd");
const meta = document.getElementById("meta");
let cell = null;
function print(s, cls) {
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = s;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}
async function api(method, path, body) {
  const r = await fetch(path, {method,
    headers: {"content-type": "application/json"},
    body: body ? JSON.stringify(body) : undefined});
  return r.json();
}
addEventListener("load", async () => {
  try {
    const c = await api("POST", "/api/cells");
    cell = c.id;
    meta.textContent = "cell " + c.id + " (isolated: namespaces+landlock+seccomp+cgroup)";
    print("$ welcome — the cell is ready\\n\\n");
  } catch (e) { meta.textContent = "failed to start cell"; }
});
addEventListener("beforeunload", () => {
  if (cell) navigator.sendBeacon("/api/cells/" + cell + "/delete");
});
cmd.addEventListener("keydown", async (e) => {
  if (e.key !== "Enter" || !cmd.value.trim() || !cell) return;
  const c = cmd.value; cmd.value = "";
  print("$ " + c + "\\n");
  try {
    const r = await api("POST", "/api/cells/" + cell + "/exec", {cmd: c});
    if (r.stdout) print(r.stdout);
    if (r.code !== 0) print("[exit " + r.code + "]\\n", "err");
  } catch (err) { print("[gateway error]\\n", "err"); }
  print("\\n");
});
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def log_message(self, *a):   # quiet
        pass

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/cells":
            with lock:
                self._json([{"id": i, "sock": c["sock"],
                             "uptime": int(time.time() - c["started"]),
                             "execs": c["execs"]} for i, c in cells.items()])
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/cells":
            try:
                cid, sock = cell_create()
                self._json({"id": cid, "sock": sock})
            except Exception as e:
                self._json({"error": str(e)}, 500)
            return
        m = re.fullmatch(r"/api/cells/(\d+)/exec", self.path)
        if m:
            try:
                out, code = cell_exec(m.group(1), self._body().get("cmd", ""))
                self._json({"stdout": out, "code": code})
            except KeyError:
                self._json({"error": "no such cell"}, 404)
            except subprocess.TimeoutExpired:
                self._json({"stdout": "", "code": 124, "error": "timeout"}, 504)
            return
        m = re.fullmatch(r"/api/cells/(\d+)/delete", self.path)
        if m:                                # sendBeacon can't DELETE
            cell_delete(m.group(1))
            self._json({})
            return
        self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        m = re.fullmatch(r"/api/cells/(\d+)", self.path)
        if m:
            cell_delete(m.group(1))
            self._json({})
        else:
            self._json({"error": "not found"}, 404)


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"agentcell gateway on http://127.0.0.1:{port}  (demo: no auth)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with lock:
            ids = list(cells)
        for cid in ids:
            cell_delete(cid)


if __name__ == "__main__":
    main()
