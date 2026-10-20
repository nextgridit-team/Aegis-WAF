#!/usr/bin/env python3
"""Destructive only to a dedicated test deployment and its dedicated PG cluster.

Requires AEGIS_WAF_TEST_CREDENTIALS_FILE ({key,secret,password}), PG_CTL, PG_DATA.
Assumes the locally built app listens at 18080/18443/19090. The fixture creates
and deletes an 'Outage test' site/certificate and stops/starts the supplied DB.
"""
import contextlib
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

state = json.loads(Path(os.environ["AEGIS_WAF_TEST_CREDENTIALS_FILE"]).read_text())
pg_ctl, pg_data = os.environ["PG_CTL"], os.environ["PG_DATA"]
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""

def request(path, method="GET", body=None, expected=200):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request("http://127.0.0.1:19090" + path, data=data, method=method,
        headers={"Content-Type": "application/json", "X-Requested-With": "aegis-waf", "X-CSRF-Token": csrf})
    try:
        response = client.open(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read()
        assert response.status == expected, (path, response.status, payload)
        return json.loads(payload)

class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"outage test upstream")
    def log_message(self, *args):
        pass

upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 18081), Upstream)
threading.Thread(target=upstream.serve_forever, daemon=True).start()

def public(tls=False):
    if tls:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection("outage.example.com", 18443, timeout=5, context=ctx)
        conn._create_connection = lambda address, *args, **kw: socket.create_connection(("127.0.0.1", 18443), timeout=5)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
    with contextlib.closing(conn):
        conn.request("GET", "/", headers={"Host": "outage.example.com"})
        response = conn.getresponse()
        assert response.status == 200, response.status
        assert response.read() == b"outage test upstream"

def eventually(fn):
    last = None
    for _ in range(120):
        try:
            fn()
            return
        except Exception as error:
            last = error
            time.sleep(0.1)
    raise AssertionError("Condition did not converge") from last

def pg(action):
    args = [pg_ctl, "-D", pg_data, "-w"]
    args += ["-m", "fast", "stop"] if action == "stop" else ["-l", "/tmp/aegis-waf-postgres.log", "-o", "-h 127.0.0.1 -p 55432 -k /tmp", "start"]
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

replica = None
stopped = False
cert_id = site_id = None
try:
    login = request("/api/login", "POST", {"username": "browser-admin", "password": state["password"]})
    csrf = login["csrf"]
    with tempfile.TemporaryDirectory(prefix="aegis-waf-outage-") as temp:
        cert, key = Path(temp) / "cert.pem", Path(temp) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "90", "-subj", "/CN=outage.example.com", "-addext", "subjectAltName=DNS:outage.example.com", "-addext", "basicConstraints=critical,CA:FALSE"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert_id = request("/api/certificates", "POST", {"name": "Outage test", "chain_pem": cert.read_text(), "private_key_pem": key.read_text()})["id"]
    site_id = request("/api/sites", "POST", {"name": "Outage test", "hostnames": ["outage.example.com"], "upstream": "http://127.0.0.1:18081", "certificate_id": cert_id, "redirect_https": False, "preserve_host": True, "enabled": True})["id"]
    eventually(lambda: public(True))
    public()
    pg("stop")
    stopped = True
    time.sleep(2.5)
    public()
    public(True)
    request("/readyz")
    request("/livez")
    request("/api/sites", "POST", {}, expected=503)
    env = dict(os.environ, DATABASE_URL="postgres://aegis_waf@127.0.0.1:55432/postgres?sslmode=disable",
        ENCRYPTION_KEY=state["key"], BOOTSTRAP_SECRET=state["secret"], HTTP_ADDR="127.0.0.1:18082",
        HTTPS_ADDR="127.0.0.1:18445", MANAGEMENT_ADDR="127.0.0.1:19092")
    binary = Path(__file__).resolve().parents[1] / "bin/aegis-waf"
    replica = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def check_new_ready(expected):
        try:
            response = urllib.request.urlopen("http://127.0.0.1:19092/readyz", timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == expected
    eventually(lambda: check_new_ready(503))
    pg("start")
    stopped = False
    eventually(lambda: check_new_ready(200))
    public(True)
    request("/api/me")
    print("PASS: actual PostgreSQL outage preserves HTTP/TLS, administration fails accurately, new replica stays unready, both recover when PostgreSQL returns.")
finally:
    if stopped:
        pg("start")
    if replica:
        replica.send_signal(signal.SIGTERM)
        replica.wait(timeout=20)
        assert replica.returncode == 0, "replica did not shut down gracefully"
    if site_id:
        eventually(lambda: request(f"/api/sites/{site_id}", "DELETE"))
    if cert_id:
        request(f"/api/certificates/{cert_id}", "DELETE")
    upstream.shutdown()
    upstream.server_close()
