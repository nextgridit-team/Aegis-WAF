#!/usr/bin/env python3
"""Run race-enabled Go tests against an isolated PostgreSQL container."""
import os
import secrets
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
name = 'aegis-go-' + secrets.token_hex(4)
rate_image = os.environ.get('AEGIS_TEST_RATE_STATE_IMAGE', '')
rate_name = name + '-rates'
rate_password = secrets.token_urlsafe(24)
def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)
try:
    run('docker', 'network', 'create', name, stdout=subprocess.DEVNULL)
    run('docker', 'run', '-d', '--name', name, '--network', name, '--network-alias', 'db', '-e', 'POSTGRES_USER=aegis_waf', '-e', 'POSTGRES_DB=testdb', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '--tmpfs', '/var/lib/postgresql', 'postgres:18-alpine', stdout=subprocess.DEVNULL)
    if rate_image:
        rate_args = (['--requirepass=' + rate_password, '--proactor_threads=1', '--maxmemory=512mb']
                     if 'dragonfly' in rate_image else
                     ['redis-server', '--requirepass', rate_password, '--save', '', '--appendonly', 'no', '--maxmemory', '128mb', '--maxmemory-policy', 'noeviction'])
        run('docker', 'run', '-d', '--name', rate_name, '--network', name, '--network-alias', 'rates', rate_image, *rate_args, stdout=subprocess.DEVNULL)
    for _ in range(60):
        if subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'aegis_waf', '-d', 'testdb'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('PostgreSQL did not start')
    run('docker', 'run', '--rm', '--network', name, '-v', f'{root}:/src:ro', '-w', '/src', '-e', 'TEST_DATABASE_URL=postgres://aegis_waf@db:5432/testdb?sslmode=disable', *(['-e', 'TEST_REDIS_ADDRESS=rates:6379', '-e', 'TEST_REDIS_PASSWORD=' + rate_password] if rate_image else []), 'golang:1.26-alpine', 'sh', '-c', 'apk add --no-cache gcc musl-dev >/dev/null && go test -race -count=1 ./... && go vet ./...')
finally:
    if rate_image:
        subprocess.run(['docker', 'rm', '-f', rate_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
