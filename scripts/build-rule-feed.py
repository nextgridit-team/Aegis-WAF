#!/usr/bin/env python3
"""Build/check a small release descriptor and an archive of individual rules."""
import argparse
import hashlib
import io
import json
import stat
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
folder = root / 'rules/community'
release = folder / 'release.json'
package = folder / 'community-rules.zip'
files = {}
for file in sorted(folder.rglob('*.json')):
    if file in {folder / 'manifest.json', release}:
        continue
    if file.is_symlink():
        raise SystemExit('Rule symlinks are not supported')
    raw = file.read_bytes()
    rule = json.loads(raw)
    if file.stem != rule['id'] or len(raw) > 65536:
        raise SystemExit(f'{file}: require matching stable ID and at most 64 KiB')
    files['rules/' + file.relative_to(folder).as_posix()] = raw
rule_count = len(files)
if rule_count > 2000:
    raise SystemExit('Release exceeds the 2000-entry catalogue limit')
# The default selection a following policy adopts is the whole release, and
# policies hold at most 100 rules (custom + feed combined; internal/app/
# policy.go policyRuleCount and internal/app/rules.go maxRulesPerSite).
# Publishing a larger release stalls every following client at adoption, so
# the publisher gate fails here with the overflow count instead.
per_policy_selection_cap = 100
if rule_count > per_policy_selection_cap:
    raise SystemExit(
        f'Release carries {rule_count} rules; following policies select the '
        f'whole catalogue and are capped at {per_policy_selection_cap} rules '
        f'per policy ({rule_count - per_policy_selection_cap} over). Retire '
        'rules before publishing a larger release.'
    )
files['LICENSE'] = (root / 'LICENSE').read_bytes()
files['LICENSES/nuclei-templates.txt'] = (root / 'third_party_licenses/nuclei-templates.txt').read_bytes()
if sum(map(len, files.values())) > 8 * 1024 * 1024:
    raise SystemExit('Expanded package exceeds 8 MiB')

# Reuse a matching archive so unchanged source checks do not depend on the
# producer's zlib version. New archives use fixed ordering, timestamps and modes.
def archive_matches(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if archive.namelist() != sorted(files):
                return False
            for member in archive.infolist():
                if member.file_size != len(files[member.filename]) or member.file_size > 65536:
                    return False
                if archive.read(member) != files[member.filename]:
                    return False
            return True
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return False

raw = package.read_bytes() if package.exists() else b''
if not archive_matches(raw):
    if args.check:
        raise SystemExit('Package is stale; run python3 scripts/build-rule-feed.py')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content, compresslevel=9)
    raw = buffer.getvalue()
if len(raw) > 8 * 1024 * 1024:
    raise SystemExit('Package exceeds 8 MiB')
old = json.loads(release.read_text()) if release.exists() else None
legacy = json.loads((folder / 'manifest.json').read_text()) if (folder / 'manifest.json').exists() else {'revision': 0}
version = old['revision'] if old else legacy['revision'] + 1
new = {
    'schema_version': 3,
    'name': 'Aegis community mitigation rules',
    'revision': version,
    'package': {'path': package.name, 'sha256': hashlib.sha256(raw).hexdigest(), 'rule_count': rule_count, 'size_bytes': len(raw)},
}
# A release signature covers the package bytes and survives regeneration while
# those bytes are unchanged; a changed package drops it until the release
# workflow signs the new archive.
signature = old.get('signature') if old else None
if signature is not None:
    if (not isinstance(signature, dict) or signature.get('algorithm') != 'cosign-keyless-v1'
            or not isinstance(signature.get('certificate'), str) or not isinstance(signature.get('value'), str)
            or not isinstance(signature.get('integrated_time_ms'), int) or isinstance(signature.get('integrated_time_ms'), bool)):
        raise SystemExit('Existing release signature is malformed; remove it and re-sign the release')
    if old['package']['sha256'] == new['package']['sha256']:
        new['signature'] = signature
if old and new != old:
    new['revision'] += 1
text = json.dumps(new, indent=2) + '\n'
if args.check:
    if not release.exists() or release.read_text() != text:
        raise SystemExit('Release descriptor is stale; run python3 scripts/build-rule-feed.py')
    print(f'PASS: release {new["revision"]}, {rule_count} individual rules, {len(raw)} archive bytes')
else:
    package.write_bytes(raw)
    release.write_text(text)
    print(f'Release {new["revision"]}: {rule_count} individual rules; {len(text)} descriptor bytes; {len(raw)} archive bytes')
