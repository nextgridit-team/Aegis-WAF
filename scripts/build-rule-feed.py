#!/usr/bin/env python3
"""Build/check the public manifest from independently maintained rule JSON files."""
import argparse, hashlib, json
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
folder=Path(__file__).resolve().parents[1]/'rules/community'
entries=[]
for file in sorted(folder.glob('*.json')):
    if file.name=='manifest.json':continue
    data=json.loads(file.read_text());assert file.stem==data['id'],file
    entries.append({'id':data['id'],'path':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
manifest=folder/'manifest.json'
old=json.loads(manifest.read_text()) if manifest.exists() else {'revision':0,'rules':[]}
changed=entries!=old['rules']
new={'schema_version':2,'name':'Aegis community mitigation rules','revision':old['revision']+(1 if changed else 0),'rules':entries}
raw=json.dumps(new,indent=2)+'\n'
if args.check:
    if not manifest.exists() or manifest.read_text()!=raw:raise SystemExit('Manifest is stale; run python3 scripts/build-rule-feed.py')
    print(f'PASS: {len(entries)} individual rules match manifest checksums')
else:
    manifest.write_text(raw);print(f'Manifest revision {new["revision"]}: {len(entries)} rules')
