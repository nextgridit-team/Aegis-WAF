#!/usr/bin/env python3
"""Exercise the PR revision gate with a disposable git repository."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
class RuleRevisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='aegis-rule-review-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'rules/community', self.root / 'rules/community')
        (self.root / 'scripts').mkdir()
        for name in ('build-rule-feed.py', 'check-rule-revisions.py'):
            shutil.copy(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        self.git('init', '-q')
        self.git('-c', 'user.name=Rule test', '-c', 'user.email=rule-test@example.invalid', 'add', '.')
        self.git('-c', 'user.name=Rule test', '-c', 'user.email=rule-test@example.invalid', 'commit', '-qm', 'Reviewed base')
        self.rule = self.root / 'rules/community/node-brotli-request-guard.json'
    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
    def check(self):
        return subprocess.run(['python3', 'scripts/check-rule-revisions.py', '--base-ref', 'HEAD'], cwd=self.root, capture_output=True).returncode
    def update(self, **fields):
        data = json.loads(self.rule.read_text()); data.update(fields)
        self.rule.write_text(json.dumps(data, indent=2) + '\n')
    def generate(self):
        subprocess.run(['python3', 'scripts/build-rule-feed.py'], cwd=self.root, check=True, capture_output=True)
    def test_unchanged_passes(self):
        self.assertEqual(self.check(), 0)
    def test_same_revision_change_fails(self):
        self.update(description='Changed applicability without review revision')
        self.generate()
        self.assertNotEqual(self.check(), 0)
    def test_revision_without_manifest_bump_fails(self):
        self.update(revision=2)
        self.assertNotEqual(self.check(), 0)
    def test_revision_with_manifest_passes(self):
        self.update(revision=2, description='Updated applicability')
        self.generate()
        self.assertEqual(self.check(), 0)
    def test_stable_id_change_fails(self):
        self.update(id='different-id', revision=2)
        self.assertNotEqual(self.check(), 0)

if __name__ == '__main__': unittest.main()
