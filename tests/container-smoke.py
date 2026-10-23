#!/usr/bin/env python3
"""Build first: docker build -t aegis-waf:verification .

Run: python3 tests/container-smoke.py [image]
Creates an isolated Compose project with random localhost ports, fresh secrets,
and a disposable PostgreSQL volume. Removes only its own project on exit.
"""
import contextlib
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "aegis-waf:verification"
PROJECT = "aegis-verify-" + secrets.token_hex(4)


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"Command failed: {args[0]} {args[1]}\n{result.stderr}")
    return result


def eventually(fn, seconds=120):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except (AssertionError, OSError, urllib.error.URLError, RuntimeError) as error:
            last = error
            time.sleep(0.5)
    raise AssertionError("Timed out waiting for test condition") from last


with tempfile.TemporaryDirectory(prefix="aegis-container-") as temp:
    temp = Path(temp)
    (temp / "scripts").mkdir()
    shutil.copyfile(ROOT / "scripts/bootstrap-secrets.py", temp / "scripts/bootstrap-secrets.py")
    run(sys.executable, str(temp / "scripts/bootstrap-secrets.py"))
    secret_dir = temp / "secrets"
    override = {
        "services": {
            "app": {"image": IMAGE, "pull_policy": "never"},
            "app_alt": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23456:23456"},
            "app_fresh": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23457:23457", "profiles": ["fresh"]},
            "upstream": {
                "image": "node:22-alpine", "pull_policy": "if_not_present", "user": "10001:10001", "entrypoint": ["node"],
                "command": ["-e", "require('http').createServer((req,res)=>res.end('container verified upstream')).listen(8000,'0.0.0.0')"],
                "read_only": True, "tmpfs": ["/tmp:rw,noexec,nosuid,size=1m,mode=1777"],
                "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                "healthcheck": {"disable": True},
            },
        },
        "secrets": {name: {"file": str(secret_dir / name)} for name in
                    ("database_url", "postgres_password", "encryption_key", "bootstrap_secret")},
    }
    overlay = temp / "override.json"
    overlay.write_text(json.dumps(override))
    env_old = {key: os.environ.get(key) for key in ("HTTP_PUBLISH", "HTTPS_PUBLISH", "MANAGEMENT_PUBLISH")}
    for key in env_old:
        os.environ[key] = "127.0.0.1:0"
    compose = ["docker", "compose", "-p", PROJECT, "-f", str(ROOT / "compose.yaml"), "-f", str(overlay)]

    def dc(*args, **kw):
        return run(*compose, *args, **kw)

    def container(service):
        return dc("ps", "-a", "-q", service).stdout.strip()

    def port(service, internal):
        value = dc("port", service, str(internal)).stdout.strip()
        assert value.startswith("127.0.0.1:"), "Test port is not bound to localhost"
        return int(value.rsplit(":", 1)[1])

    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    csrf = ""

    def api(service, path, method="GET", body=None, expected=200):
        req = urllib.request.Request(f"http://127.0.0.1:{port(service, 9090)}{path}",
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={"Content-Type": "application/json", "X-Requested-With": "aegis-waf", "X-CSRF-Token": csrf})
        try:
            response = client.open(req, timeout=40)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = json.loads(response.read())
            assert response.status == expected, f"{path}: HTTP {response.status}, expected {expected}"
            return data

    def public(service, tls=False):
        published = port(service, 8443 if tls else 8080)
        if tls:
            conn = http.client.HTTPSConnection("container.example.com", published,
                context=ssl._create_unverified_context(), timeout=5)
            conn._create_connection = lambda *args, **kw: socket.create_connection(("127.0.0.1", published), timeout=5)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", published, timeout=5)
        with contextlib.closing(conn):
            conn.request("GET", "/", headers={"Host": "container.example.com"})
            res = conn.getresponse()
            assert res.status == 200, f"Public listener returned {res.status}"
            assert res.read() == b"container verified upstream"

    try:
        dc("config", "--quiet")
        dc("up", "--no-build", "--wait", "--wait-timeout", "120", "db", "upstream", "app", "app_alt")
        for service, uid in (("app", "10001"), ("app_alt", "23456")):
            cid = container(service)
            data = json.loads(run("docker", "inspect", cid).stdout)[0]
            host = data["HostConfig"]
            assert host["ReadonlyRootfs"] and not host["Privileged"]
            assert host["CapDrop"] == ["ALL"]
            assert host["NetworkMode"] != "host"
            assert any(v.startswith("no-new-privileges") for v in host["SecurityOpt"])
            assert not any(m["Destination"] == "/var/run/docker.sock" or m["Type"] == "volume" for m in data["Mounts"])
            assert run("docker", "exec", cid, "id", "-u").stdout.strip() == uid
            run("docker", "exec", cid, "sh", "-c", "test -r /run/secrets/encryption_key && test -r /etc/ssl/certs/ca-certificates.crt && test -w /tmp && touch /tmp/probe && rm /tmp/probe")
            probe = run("docker", "exec", cid, "touch", "/etc/aegis-write-probe", check=False)
            assert probe.returncode != 0 and "Read-only file system" in probe.stderr
            run("docker", "exec", cid, "aegis-waf", "healthcheck")
        print("PASS: image healthchecks, UID 10001 and arbitrary UID 23456, read-only root, writable tmpfs, CA/secret readability, no capabilities/privilege/socket/persistent app volume", flush=True)
        password = secrets.token_urlsafe(32)
        api("app", "/api/setup", "POST", {"username": "container-admin", "password": password,
            "secret": (secret_dir / "bootstrap_secret").read_text().strip()}, 201)
        csrf = api("app", "/api/login", "POST", {"username": "container-admin", "password": password})["csrf"]
        api("app_alt", "/api/me")
        chain, key = temp / "chain.pem", temp / "key.pem"
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(key), "-out", str(chain), "-days", "90", "-subj", "/CN=container.example.com",
            "-addext", "subjectAltName=DNS:container.example.com", "-addext", "basicConstraints=critical,CA:FALSE")
        cert_id = api("app", "/api/certificates", "POST", {"name": "Container verification",
            "chain_pem": chain.read_text(), "private_key_pem": key.read_text()})["id"]
        api("app", "/api/sites", "POST", {"name": "Container verification", "hostnames": ["container.example.com"],
            "upstream": "http://upstream:8000", "certificate_id": cert_id, "redirect_https": False,
            "preserve_host": True, "enabled": True})
        for service in ("app", "app_alt"):
            eventually(lambda: public(service, True))
            public(service)
        assert "key_cipher" not in json.dumps(api("app_alt", "/api/certificates"))
        assert "PRIVATE KEY" not in json.dumps(api("app_alt", "/api/certificates"))
        terms = api("app", "/api/acme/directory?url=staging")
        assert terms["terms_url"].startswith("https://")
        print("PASS: setup, cross-replica sessions, encrypted certificate upload, cached HTTP/TLS routing on both replicas, private-key readback exclusion, ACME staging directory connectivity with packaged CAs", flush=True)
        dc("stop", "db")
        time.sleep(3)
        for service in ("app", "app_alt"):
            public(service)
            public(service, True)
            api(service, "/readyz")
        api("app", "/api/sites", "POST", {}, 503)
        dc("up", "--no-build", "--no-deps", "-d", "app_fresh")
        eventually(lambda: api("app_fresh", "/livez"))
        api("app_fresh", "/readyz", expected=503)
        dc("start", "db")
        eventually(lambda: api("app_fresh", "/readyz"))
        eventually(lambda: public("app_fresh", True))
        api("app_alt", "/api/me")
        print("PASS: database outage preserves loaded HTTP/TLS routes, writes fail accurately, fresh replica stays unready and recovers", flush=True)
        dc("restart", "app")
        eventually(lambda: api("app", "/readyz"))
        public("app", True)
        api("app", "/api/me")
        dc("stop", "app", "app_alt", "app_fresh")
        for service in ("app", "app_alt", "app_fresh"):
            data = json.loads(run("docker", "inspect", container(service)).stdout)[0]
            assert data["State"]["ExitCode"] == 0 and not data["State"]["OOMKilled"]
        print("PASS: restart reloads certificate/configuration/sessions from PostgreSQL; all replicas shut down gracefully", flush=True)
    except BaseException:
        print(dc("logs", "--no-color", "--tail", "30", "app", "app_alt", "app_fresh", check=False).stdout, file=sys.stderr)
        raise
    finally:
        dc("--profile", "fresh", "down", "--volumes", "--remove-orphans", check=False)
        for name, value in env_old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
