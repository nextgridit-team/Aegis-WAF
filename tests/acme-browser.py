#!/usr/bin/env python3
"""Run the browser's certificate-to-proxy flow against real Pebble HTTP-01.

Build aegis-waf:ui-verification first. Requires Docker Compose, Node, OpenSSL,
Python 3 and `npm --prefix tests ci`; set BROWSER_EXECUTABLE when necessary.
All test services, certificates and secrets are isolated and removed on exit.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
IMAGE = sys.argv[1] if len(sys.argv) > 1 else 'aegis-waf:ui-verification'
PROJECT = 'aegis-acme-ui-' + secrets.token_hex(4)
ARTIFACTS = Path(os.environ.get('BROWSER_ARTIFACT_DIR', '/tmp/aegis-ui-review')).resolve()
ARTIFACTS.mkdir(parents=True, exist_ok=True)


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} {args[1]} failed:\n{result.stderr}\n{result.stdout}')
    return result


with tempfile.TemporaryDirectory(prefix='aegis-acme-ui-') as work:
    work = Path(work)
    (work / 'scripts').mkdir()
    shutil.copyfile(ROOT / 'scripts/bootstrap-secrets.py', work / 'scripts/bootstrap-secrets.py')
    run(sys.executable, str(work / 'scripts/bootstrap-secrets.py'))
    secret_dir = work / 'secrets'
    ca, key = work / 'pebble.pem', work / 'pebble.key'
    run('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(key), '-out', str(ca), '-days', '2', '-subj', '/CN=Aegis isolated ACME test', '-addext', 'subjectAltName=DNS:pebble', '-addext', 'basicConstraints=critical,CA:TRUE')
    key.chmod(0o444)
    ca.chmod(0o444)
    config = work / 'pebble.json'
    config.write_text(json.dumps({'pebble': {'listenAddress': '0.0.0.0:14000', 'managementListenAddress': '0.0.0.0:15000', 'certificate': '/test/pebble.pem', 'privateKey': '/test/pebble.key', 'httpPort': 8080, 'tlsPort': 8443, 'retryAfter': {'authz': 1, 'order': 1}, 'profiles': {'default': {'description': 'Isolated test certificates', 'validityPeriod': 7776000}}}}))
    config.chmod(0o444)
    overrides = {'services': {
        'app': {'image': IMAGE, 'pull_policy': 'never', 'environment': {'SSL_CERT_FILE': '/test-trust/pebble.pem'}, 'volumes': [f'{ca}:/test-trust/pebble.pem:ro']},
        'app_alt': {'extends': {'file': str(ROOT / 'compose.yaml'), 'service': 'app'}, 'image': IMAGE, 'pull_policy': 'never', 'user': '23456:23456', 'environment': {'SSL_CERT_FILE': '/test-trust/pebble.pem'}, 'volumes': [f'{ca}:/test-trust/pebble.pem:ro'], 'networks': {'default': {'aliases': ['app.example.test', 'manual.example.test']}}},
        'pebble': {'image': 'ghcr.io/letsencrypt/pebble:latest', 'command': ['-config', '/test/pebble.json', '-strict=false'], 'environment': {'PEBBLE_VA_NOSLEEP': '1', 'PEBBLE_WFE_NONCEREJECT': '0'}, 'ports': ['127.0.0.1:0:15000'], 'volumes': [f'{config}:/test/pebble.json:ro', f'{ca}:/test/pebble.pem:ro', f'{key}:/test/pebble.key:ro']},
        'upstream': {'image': 'node:22-alpine', 'user': '10001:10001', 'entrypoint': ['node'], 'command': ['-e', "require('http').createServer((req,res)=>{res.setHeader('Server','test-upstream');res.setHeader('X-Seen-Client-IP',req.headers['x-forwarded-for']||'');res.setHeader('X-Seen-Test-Header',req.headers['x-aegis-test']||'');res.setHeader('X-Seen-Stripped-Header',req.headers['x-strip-me']||'');res.end('ACME verified application')}).listen(8000,'0.0.0.0')"], 'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true']},
    }, 'secrets': {name: {'file': str(secret_dir / name)} for name in ('database_url', 'postgres_password', 'encryption_key', 'bootstrap_secret')}}
    overlay = work / 'compose.json'
    overlay.write_text(json.dumps(overrides))
    env = dict(os.environ, HTTP_PUBLISH='127.0.0.1:0', HTTPS_PUBLISH='127.0.0.1:0', MANAGEMENT_PUBLISH='127.0.0.1:0')
    compose = ['docker', 'compose', '-p', PROJECT, '-f', str(ROOT / 'compose.yaml'), '-f', str(overlay)]

    def dc(*args, check=True):
        return run(*compose, *args, check=check, env=env)

    def port(service, target):
        return dc('port', service, str(target)).stdout.strip().rsplit(':', 1)[1]

    try:
        dc('up', '--no-build', '--wait', '--wait-timeout', '120', 'db', 'pebble', 'upstream', 'app', 'app_alt')
        # Trust the test authority's HTTPS endpoint, then retrieve its issuing root.
        trust = ssl.create_default_context(cafile=str(ca))
        trust.check_hostname = False
        endpoint = f'https://127.0.0.1:{port("pebble", 15000)}/roots/0'
        root = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(endpoint, context=trust, timeout=3) as response:
                    root = response.read().decode()
                assert root.startswith('-----BEGIN CERTIFICATE-----')
                break
            except Exception:
                time.sleep(1)
        if root is None:
            raise RuntimeError('Pebble did not expose its issuing root')
        root_file = work / 'issuer.pem'
        root_file.write_text(root)
        credentials = work / 'credentials.json'
        credentials.write_text(json.dumps({'secret': (secret_dir / 'bootstrap_secret').read_text().strip(), 'password': secrets.token_urlsafe(32)}))
        credentials.chmod(0o600)
        browser_env = dict(os.environ, BROWSER_CREDENTIALS_FILE=str(credentials), BROWSER_BASE_URL=f'http://127.0.0.1:{port("app", 9090)}', BROWSER_PROXY_URL=f'http://127.0.0.1:{port("app", 8080)}', BROWSER_HTTPS_PORT=port('app', 8443), BROWSER_ALT_HTTPS_PORT=port('app_alt', 8443), BROWSER_ACME_DIRECTORY='https://pebble:14000/dir', BROWSER_ISSUER_ROOT=str(root_file), BROWSER_UPSTREAM_URL='http://upstream:8000', BROWSER_ARTIFACT_DIR=str(ARTIFACTS))
        result = run('node', str(ROOT / 'tests/browser.cjs'), check=False, env=browser_env)
        print(result.stdout, end='', flush=True)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            raise RuntimeError('Browser acceptance test failed')
        # Pebble's validation is enabled: its HTTP-01 requests resolve to app_alt.
        logs = dc('logs', '--no-color', 'pebble').stdout
        (ARTIFACTS / 'pebble-validation.log').write_text(logs)
        print('PASS: real Pebble account, HTTP-01 validation through the second replica, issuance, trusted HTTPS proxy traffic, and responsive browser flows.', flush=True)
    except BaseException:
        print(dc('logs', '--no-color', '--tail', '35', 'app', 'app_alt', 'pebble', check=False).stdout, file=sys.stderr)
        raise
    finally:
        dc('down', '--volumes', '--remove-orphans', check=False)
