#!/usr/bin/env python3
"""Preserve runtime diagnostics in CI check annotations when log access is restricted."""
import subprocess
import sys
from pathlib import Path
result = subprocess.run([sys.executable, str(Path(__file__).with_name("container-smoke.py")), *sys.argv[1:]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
print(result.stdout, end="")
if result.returncode:
    detail = result.stdout[-4000:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=Container runtime verification failed::" + detail)
sys.exit(result.returncode)
