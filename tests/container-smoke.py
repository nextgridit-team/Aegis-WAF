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
    cache_dir = temp / "snapshot-cache"
    cache_dir.mkdir()
    cache_dir.chmod(0o777)
    override = {
        "services": {
            "app": {"image": IMAGE, "pull_policy": "never"},
            "app_alt": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23456:23456"},
            "app_tls": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23458:23458", "profiles": ["tls"], "environment": {"MANAGEMENT_TLS": "true"}},
            "app_cached": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23459:23459", "profiles": ["cache"], "environment": {"SNAPSHOT_CACHE_FILE": "/var/cache/aegis/snapshot.bin"}, "volumes": [f"{cache_dir}:/var/cache/aegis"]},
            "app_fresh": {"extends": {"file": str(ROOT / "compose.yaml"), "service": "app"}, "image": IMAGE, "pull_policy": "never", "user": "23457:23457", "profiles": ["fresh"]},
            "upstream": {
                "image": "node:22-alpine", "pull_policy": "if_not_present", "user": "10001:10001", "entrypoint": ["node"],
                "command": ["-e", "require('http').createServer((req,res)=>res.end('container verified upstream')).listen(8000,'0.0.0.0')"],
                "ports": ["127.0.0.1:0:8000"],
                "read_only": True, "tmpfs": ["/tmp:rw,noexec,nosuid,size=1m,mode=1777"],
                "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
                "healthcheck": {"test": ["CMD", "node", "-e", "fetch('http://127.0.0.1:8000').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"], "interval": "2s", "timeout": "3s", "retries": 30},
            },
        },
        "secrets": {name: {"file": str(secret_dir / name)} for name in
                    ("database_url", "postgres_password", "encryption_key", "bootstrap_secret")},
    }
    if os.environ.get("AEGIS_COMPARE_PROXIES") == "1":
        haproxy_config = temp / "haproxy.cfg"
        haproxy_config.write_text("global\n  maxconn 4096\ndefaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n  timeout server 30s\nfrontend ingress\n  bind :8080\n  default_backend origin\nbackend origin\n  server upstream upstream:8000\n")
        nginx_config = temp / "nginx.conf"
        nginx_config.write_text("worker_processes auto;\npid /tmp/nginx.pid;\nerror_log /dev/stderr warn;\nevents { worker_connections 4096; }\nhttp {\n access_log off;\n client_body_temp_path /tmp/client_temp; proxy_temp_path /tmp/proxy_temp;\n fastcgi_temp_path /tmp/fastcgi_temp; uwsgi_temp_path /tmp/uwsgi_temp; scgi_temp_path /tmp/scgi_temp;\n upstream origin { server upstream:8000; keepalive 32; }\n server { listen 8080; location / { proxy_pass http://origin; proxy_http_version 1.1; proxy_set_header Connection \"\"; proxy_set_header Host $http_host; proxy_buffering off; proxy_request_buffering off; } }\n}\n")
        for file in (haproxy_config, nginx_config):
            file.chmod(0o644)
        for service, image, entrypoint, command, config, target in (
            ("reference_haproxy", "haproxy:3.2-alpine", ["haproxy"], ["-W", "-db", "-f", "/etc/haproxy/haproxy.cfg"], haproxy_config, "/etc/haproxy/haproxy.cfg"),
            ("reference_nginx", "nginx:stable-alpine", ["nginx"], ["-g", "daemon off;"], nginx_config, "/etc/nginx/nginx.conf"),
        ):
            override["services"][service] = {"image": image, "profiles": ["reference"], "entrypoint": entrypoint, "command": command, "user": "10001:10001", "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m,mode=1777"], "ports": ["127.0.0.1:0:8080"], "volumes": [f"{config}:{target}:ro"], "depends_on": {"upstream": {"condition": "service_healthy"}}}
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
        site_id = api("app", "/api/sites", "POST", {"name": "Container verification", "hostnames": ["container.example.com"],
            "upstream": "http://upstream:8000", "certificate_id": cert_id, "redirect_https": False,
            "preserve_host": True, "enabled": True})["id"]
        for service in ("app", "app_alt"):
            eventually(lambda: public(service, True))
            public(service)
        assert "key_cipher" not in json.dumps(api("app_alt", "/api/certificates"))
        assert "PRIVATE KEY" not in json.dumps(api("app_alt", "/api/certificates"))
        terms = api("app", "/api/acme/directory?url=staging")
        assert terms["terms_url"].startswith("https://")
        print("PASS: setup, cross-replica sessions, encrypted certificate upload, cached HTTP/TLS routing on both replicas, private-key readback exclusion, ACME staging directory connectivity with packaged CAs", flush=True)
        if os.environ.get("AEGIS_BENCHMARK_REPORT"):
            import importlib.util
            module_spec = importlib.util.spec_from_file_location("latency_benchmark", ROOT / "tests/latency-benchmark.py")
            benchmark = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(benchmark)
            report = {"image": IMAGE, "workload": "HTTP/1.1 keep-alive GET, small fixed body; local closed-loop client and Docker ports", "phases": []}
            if os.environ.get("AEGIS_COMPARE_PROXIES") == "1":
                dc("up", "--no-build", "-d", "reference_haproxy", "reference_nginx")
                for service in ("reference_haproxy", "reference_nginx"):
                    eventually(lambda service=service: benchmark.measure(port(service, 8080), requests=16, concurrency=1))
                    report["phases"].append({"name": service, **benchmark.measure(port(service, 8080))})
                    info = json.loads(run("docker", "inspect", container(service)).stdout)[0]
                    report.setdefault("reference_images", {})[service] = {"tag": info["Config"]["Image"], "image_id": info["Image"]}
            for name, service, listener in (("direct_upstream", "upstream", 8000), ("gateway_0_rules", "app", 8080)):
                report["phases"].append({"name": name, **benchmark.measure(port(service, listener))})
            installed = 0
            for count in (10, 100):
                for n in range(installed, count):
                    rule = api("app", "/api/rules", "POST", {"schema_version": 1, "name": f"Benchmark {n}", "scope": {"site_id": site_id}, "all": [{"field": "path", "op": "equals", "value": f"/never-match-{n}"}], "action": "observe", "ttl_seconds": 3600})["id"]
                    api("app", f"/api/rules/{rule}/activate", "POST", {"action": "observe", "ttl_seconds": 3600})
                installed = count
                time.sleep(2.5)
                report["phases"].append({"name": f"gateway_{count}_rules", **benchmark.measure(port("app", 8080))})
            report["status_after_load"] = api("app", "/api/status")
            Path(os.environ["AEGIS_BENCHMARK_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")
            print("PASS: latency benchmark written to " + os.environ["AEGIS_BENCHMARK_REPORT"], flush=True)
        dc("up", "--no-build", "--no-deps", "--wait", "--wait-timeout", "120", "app_cached")
        eventually(lambda: api("app_cached", "/readyz"))
        assert (cache_dir / "snapshot.bin").exists(), "Recovery snapshot was not written"
        dc("stop", "app_cached")
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
        dc("up", "--no-build", "--no-deps", "-d", "app_cached")
        eventually(lambda: api("app_cached", "/readyz"))
        public("app_cached")
        public("app_cached", True)
        api("app_cached", "/api/me", expected=503)
        print("PASS: optional sealed cache restores HTTP/TLS on restart during database outage; sessions still require PostgreSQL", flush=True)
        dc("start", "db")
        eventually(lambda: api("app_fresh", "/readyz"))
        eventually(lambda: public("app_fresh", True))
        api("app_alt", "/api/me")
        print("PASS: database outage preserves loaded HTTP/TLS routes, writes fail accurately, fresh replica stays unready and recovers", flush=True)
        dc("restart", "app")
        eventually(lambda: api("app", "/readyz"))
        public("app", True)
        api("app", "/api/me")
        dc("stop", "app", "app_alt", "app_fresh", "app_cached")
        for service in ("app", "app_alt", "app_fresh", "app_cached"):
            data = json.loads(run("docker", "inspect", container(service)).stdout)[0]
            assert data["State"]["ExitCode"] == 0 and not data["State"]["OOMKilled"]
        print("PASS: restart reloads certificate/configuration/sessions from PostgreSQL; all replicas shut down gracefully", flush=True)
        # Enable direct HTTPS on a new replica, reusing the stored certificate.
        dc("up", "--no-build", "--wait", "--wait-timeout", "120", "app_tls")
        run("docker", "exec", container("app_tls"), "aegis-waf", "healthcheck")
        tls_port = port("app_tls", 9090)
        trust = ssl.create_default_context(cadata=chain.read_text())
        def tls_request(path, method="GET", body=None, cookie="", token=""):
            conn = http.client.HTTPSConnection("container.example.com", tls_port, context=trust, timeout=10)
            conn._create_connection = lambda *args, **kw: socket.create_connection(("127.0.0.1", tls_port), timeout=10)
            with contextlib.closing(conn):
                headers = {"Content-Type":"application/json", "X-Requested-With":"aegis-waf", "Cookie":cookie, "X-CSRF-Token":token}
                conn.request(method,path,body=None if body is None else json.dumps(body).encode(),headers=headers)
                response = conn.getresponse()
                return response.status, dict(response.getheaders()), json.loads(response.read())
        status, headers, data = tls_request("/api/login","POST",{"username":"container-admin","password":password})
        assert status == 200
        cookie_header = headers["Set-Cookie"]
        assert "Secure" in cookie_header and "HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header
        cookie = cookie_header.split(";",1)[0]
        assert tls_request("/api/me",cookie=cookie)[0] == 200
        assert tls_request("/api/logout","POST",{},cookie,data["csrf"])[0] == 200
        assert tls_request("/api/me",cookie=cookie)[0] == 401
        dc("stop", "app_tls")
        print("PASS: direct management HTTPS, stored certificate trust/hostname validation, arbitrary UID, native HTTPS healthcheck, Secure cookie login/session/logout",flush=True)

    except BaseException:
        print(dc("logs", "--no-color", "--tail", "30", "app", "app_alt", "app_fresh", check=False).stdout, file=sys.stderr)
        raise
    finally:
        dc("--profile", "fresh", "--profile", "tls", "--profile", "cache", "--profile", "reference", "down", "--volumes", "--remove-orphans", check=False)
        for name, value in env_old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
