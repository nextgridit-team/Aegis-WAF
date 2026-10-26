#!/usr/bin/env python3
"""Reject changed rule bytes without an increasing per-rule/release revision."""
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
    print('No comparison base supplied; current format is checked by package/Go validation.')
    raise SystemExit(0)
# Resolve to an immutable commit before using the ref in git object expressions.
base = subprocess.check_output(['git', 'rev-parse', '--verify', '--end-of-options', base + '^{commit}'], cwd=root, text=True).strip()
paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', base, 'rules/community'], cwd=root, text=True).splitlines()
metadata = {'rules/community/manifest.json', 'rules/community/release.json'}
old_rules = {name for name in paths if name.endswith('.json') and name not in metadata}
new_rules = {file.relative_to(root).as_posix() for file in (root / 'rules/community').rglob('*.json')} - metadata
changed = old_rules != new_rules
for name in sorted(old_rules & new_rules):
    old_bytes = subprocess.check_output(['git', 'show', base + ':' + name], cwd=root)
    new_bytes = (root / name).read_bytes()
    if new_bytes == old_bytes:
        continue
    old, new = json.loads(old_bytes), json.loads(new_bytes)
    if old['id'] != new['id']:
        raise SystemExit(f'{name}: keep the stable ID; add a separate file for a new rule')
    if type(new.get('revision')) is not int or new['revision'] <= old['revision']:
        raise SystemExit(f'{name}: changed bytes require a higher revision than {old["revision"]}')
    changed = True
old_path = 'rules/community/release.json' if 'rules/community/release.json' in paths else 'rules/community/manifest.json'
old_release = json.loads(subprocess.check_output(['git', 'show', base + ':' + old_path], cwd=root))
release = json.loads((root / 'rules/community/release.json').read_text())
old_bytes = subprocess.check_output(['git', 'show', base + ':' + old_path], cwd=root)
release_changed = (root / 'rules/community/release.json').read_bytes() != old_bytes
if (changed or release_changed) and release['revision'] <= old_release['revision']:
    raise SystemExit('Rule/package changes require a higher release revision; regenerate it.')
print('PASS: existing rule IDs are stable and changed files increase revisions')
