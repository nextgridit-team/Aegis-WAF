#!/usr/bin/env python3
"""Reject changed rule bytes without an increasing per-rule/manifest revision."""
import argparse
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--base-ref', default='')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
base = args.base_ref
if not base or set(base) == {'0'}:
    print('No comparison base supplied; current format is checked by manifest/Go validation.')
    raise SystemExit(0)
# Resolve to an immutable commit before using the ref in git object expressions.
base = subprocess.check_output(['git', 'rev-parse', '--verify', '--end-of-options', base + '^{commit}'], cwd=root, text=True).strip()
paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', base, 'rules/community'], cwd=root, text=True).splitlines()
changed = False
for name in paths:
    if not name.endswith('.json'):
        continue
    current = root / name
    old_bytes = subprocess.check_output(['git', 'show', base + ':' + name], cwd=root)
    if not current.exists():
        changed = True
        continue
    new_bytes = current.read_bytes()
    if new_bytes == old_bytes:
        continue
    old, new = json.loads(old_bytes), json.loads(new_bytes)
    if Path(name).name != 'manifest.json' and old['id'] != new['id']:
        raise SystemExit(f'{name}: keep the stable ID; add a separate file for a new rule')
    if type(new.get('revision')) is not int or new['revision'] <= old['revision']:
        raise SystemExit(f'{name}: changed bytes require a higher revision than {old["revision"]}')
    if Path(name).name != 'manifest.json':
        changed = True
old_manifest = json.loads(subprocess.check_output(['git', 'show', base + ':rules/community/manifest.json'], cwd=root))
manifest = json.loads((root / 'rules/community/manifest.json').read_text())
if changed and manifest['revision'] <= old_manifest['revision']:
    raise SystemExit('Rule changes require a higher manifest revision; regenerate it.')
print('PASS: existing rule IDs are stable and changed files increase revisions')
