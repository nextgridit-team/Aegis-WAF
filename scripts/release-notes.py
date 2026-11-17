#!/usr/bin/env python3
"""Render the markdown release notes for one Aegis-WAF version tag.

The notes state the database schema version and sealed recovery-cache format
that ship in the tagged code (extracted from the repository sources, so they
cannot drift), point at the documented upgrade order, and carry the
copy-pasteable cosign verification commands for the release image and the
rule-feed assets. The release workflow writes this output to the GitHub
Release body.
"""
import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple, NoReturn

# D1: stdlib only.
DEPENDENCIES = []


class Result(NamedTuple):
    """F2: the return matrix for fallible functions."""

    status: bool
    output: object = None
    error: str | None = None


class FullHelpArgumentParser(argparse.ArgumentParser):
    """B2: any usage error prints the full help."""

    def error(self, message: str) -> NoReturn:
        """Print the error, then the full help, and exit nonzero."""
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        self.print_help()
        sys.exit(2)


def build_parser() -> FullHelpArgumentParser:
    """Build the CLI parser with documented options and examples."""
    parser = FullHelpArgumentParser(
        description="Render markdown release notes for one Aegis-WAF version tag.",
        epilog=(
            "Examples:\n"
            "  %(prog)s --tag v0.1.0\n"
            "  %(prog)s --tag v0.1.0 --image ghcr.io/nextgridit-team/aegis-waf\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--tag", required=True,
                        help="Version tag being released, for example v0.1.0")
    parser.add_argument("--image", default="ghcr.io/nextgridit-team/aegis-waf",
                        help="Container image reference the release publishes (default: %(default)s)")
    return parser


def extract_schema_version(root: Path) -> Result:
    """Read the highest 'Version N' migration comment from schema.sql."""
    try:
        text = (root / "internal/app/schema.sql").read_text(encoding="utf-8")
    except OSError as exc:
        return Result(False, None, f"cannot read schema.sql: {exc}")
    versions = [int(m) for m in re.findall(r"^-- Version (\d+):", text, re.MULTILINE)]
    if not versions:
        return Result(False, None, "no schema version markers found in schema.sql")
    return Result(True, max(versions), None)


def extract_snapshot_format(root: Path) -> Result:
    """Read the sealed snapshot-cache format constant from snapshot_cache.go."""
    try:
        text = (root / "internal/app/snapshot_cache.go").read_text(encoding="utf-8")
    except OSError as exc:
        return Result(False, None, f"cannot read snapshot_cache.go: {exc}")
    match = re.search(r"snapshotCacheFormat = (\d+)", text)
    if not match:
        return Result(False, None, "snapshot cache format constant not found")
    return Result(True, int(match.group(1)), None)


def render(tag: str, image: str, schema: int, snapshot: int) -> str:
    """Compose the release-notes markdown."""
    identity = r"^https://github\.com/nextgridit-team/Aegis-WAF/\.github/workflows/release\.yml@refs/tags/"
    issuer = "https://token.actions.githubusercontent.com"
    return f"""## Aegis-WAF {tag}

- Database schema version: **{schema}**; sealed recovery-cache format: **{snapshot}**
- Image: `{image}:{tag}` (this build also publishes an immutable `sha-<commit>-<run-id>-<attempt>` tag)

### Upgrade order

Back up PostgreSQL and the external encryption key, then update every serving replica following [docs/updating.md](https://github.com/nextgridit-team/Aegis-WAF/blob/main/docs/updating.md) before adopting new features. Pin the version tag or its digest for production; `latest` moves nightly and is not a version. Merge the `release/{tag}` branch so the official community feed serves this signature-verified release descriptor.

### Verify this release

```sh
cosign verify --certificate-identity-regexp '{identity}' --certificate-oidc-issuer '{issuer}' {image}:{tag}
```

Download `community-rules.zip` and `community-rules.zip.bundle` from this release's assets, then:

```sh
cosign verify-blob --bundle community-rules.zip.bundle --certificate-identity-regexp '{identity}' --certificate-oidc-issuer '{issuer}' community-rules.zip
```

The official community rule feed verifies the `signature` object inside `release.json` in-process against the same identity and the pinned Sigstore Fulcio root; custom catalogue URLs are surfaced as untrusted sources.
"""


def main(argv: list | None = None) -> int:
    """Run the tool; returns the process exit code."""
    parser = build_parser()
    if argv is None and len(sys.argv) == 1:  # B1: no args -> help
        parser.print_help()
        return 2
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    schema = extract_schema_version(root)
    if not schema.status:
        print(f"error: {schema.error}", file=sys.stderr)
        return 1
    snapshot = extract_snapshot_format(root)
    if not snapshot.status:
        print(f"error: {snapshot.error}", file=sys.stderr)
        return 1
    print(render(args.tag, args.image, schema.output, snapshot.output))  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    sys.exit(main())
