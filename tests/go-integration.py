#!/usr/bin/env python3
"""Run race-enabled Go tests against an isolated PostgreSQL container."""
import secrets
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
name = 'aegis-go-' + secrets.token_hex(4)
def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)
try:
    run('docker', 'network', 'create', name, stdout=subprocess.DEVNULL)
    run('docker', 'run', '-d', '--name', name, '--network', name, '--network-alias', 'db', '-e', 'POSTGRES_USER=aegis_waf', '-e', 'POSTGRES_DB=testdb', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '--tmpfs', '/var/lib/postgresql', 'postgres:18-alpine', stdout=subprocess.DEVNULL)
    for _ in range(60):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'aegis_waf', '-d', 'testdb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('PostgreSQL did not start')
    run('docker', 'run', '--rm', '--network', name, '-v', f'{root}:/src:ro', '-w', '/src', '-e', 'TEST_DATABASE_URL=postgres://aegis_waf@db:5432/testdb?sslmode=disable', 'golang:1.26-alpine', 'sh', '-c', 'apk add --no-cache gcc musl-dev >/dev/null && go test -race -count=1 ./... && go vet ./...')
finally:
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
