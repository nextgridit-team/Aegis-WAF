#!/usr/bin/env python3
"""Embed a keyless cosign bundle into the community release descriptor.

The release workflow signs the packaged rule archive with `cosign sign-blob
--bundle`, then runs this script to embed the resulting certificate,
signature and log-integrated time into rules/community/release.json as the
`signature` object. The Aegis feed client verifies that object against its
pinned Fulcio trust anchors and the release workflow identity. The script
parses the Sigstore bundle v0.3 that cosign v3 writes (media type
application/vnd.dev.sigstore.bundle.v0.3+json, base64 DER certificate,
messageSignature.signature, tlogEntries integratedTime). It performs
structural validation only; the workflow verifies the bundle itself with
`cosign verify-blob`, and the Go client re-verifies the embedded values
against the actual archive bytes, so no cryptography is duplicated here.
"""
import argparse
import base64
import binascii
import json
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
        description="Embed a keyless cosign bundle into the community release descriptor.",
        epilog=(
            "Examples:\n"
            "  %(prog)s --bundle community-rules.zip.bundle \\\n"
            "    --release rules/community/release.json --output signed-release.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--bundle", required=True,
                        help="Path to the cosign sign-blob --bundle JSON for the rule archive")
    parser.add_argument("--release", required=True,
                        help="Path to the unsigned release.json descriptor")
    parser.add_argument("--output", required=True,
                        help="Path to write the signed descriptor (same JSON layout)")
    return parser


def bundle_time(material: dict) -> Result:
    """Validate and return the transparency-log integrated time."""
    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return Result(False, None, "bundle is missing a transparency-log entry")
    integrated = entries[0].get("integratedTime")
    if isinstance(integrated, str) and integrated.isdigit():
        integrated = int(integrated)
    if not isinstance(integrated, int) or isinstance(integrated, bool) or integrated <= 0:
        return Result(False, None, "bundle is missing a positive integratedTime")
    return Result(True, integrated, None)


def der_to_pem(der: bytes) -> str:
    """Wrap a DER certificate in a PEM document with 64-column base64."""
    encoded = base64.b64encode(der).decode("ascii")
    lines = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def chain_leaf(chain: object) -> str | None:
    """Return the first certificate rawBytes from an x509CertificateChain."""
    if not isinstance(chain, dict):
        return None
    certificates = chain.get("certificates")
    if isinstance(certificates, list) and certificates and isinstance(certificates[0], dict):
        raw = certificates[0].get("rawBytes")
        if isinstance(raw, str):
            return raw
    return None


def bundle_certificate(material: dict) -> Result:
    """Extract the leaf certificate as PEM from the verification material."""
    raw = None
    single = material.get("certificate")
    if isinstance(single, dict) and isinstance(single.get("rawBytes"), str):
        raw = single["rawBytes"]
    if raw is None:
        raw = chain_leaf(material.get("x509CertificateChain"))
    if not isinstance(raw, str) or not raw:
        return Result(False, None, "bundle is missing a certificate")
    try:
        return Result(True, der_to_pem(base64.b64decode(raw, validate=True)), None)
    except (ValueError, binascii.Error):
        return Result(False, None, "bundle certificate is not valid base64 DER")


def bundle_fields(document: dict) -> Result:
    """Extract and structurally validate the fields the descriptor embeds."""
    media = document.get("mediaType")
    if not isinstance(media, str) or not media.startswith("application/vnd.dev.sigstore.bundle"):
        return Result(False, None, f"not a Sigstore bundle: {media}")
    content = document.get("messageSignature")
    if not isinstance(content, dict) or not isinstance(content.get("signature"), str) or not content["signature"]:
        return Result(False, None, "bundle is missing messageSignature.signature")
    material = document.get("verificationMaterial")
    if not isinstance(material, dict):
        return Result(False, None, "bundle is missing verificationMaterial")
    certificate = bundle_certificate(material)
    if not certificate.status:
        return certificate
    integrated = bundle_time(material)
    if not integrated.status:
        return integrated
    return Result(True, {"value": content["signature"], "certificate": certificate.output, "integrated": integrated.output}, None)


def load_bundle(path: Path) -> Result:
    """Load and structurally validate a cosign bundle; returns its fields."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Result(False, None, f"cannot read bundle {path}: {exc}")
    if not isinstance(document, dict):
        return Result(False, None, "bundle must be a JSON object")
    return bundle_fields(document)


def load_release(path: Path) -> Result:
    """Load the unsigned descriptor and check it is a schema 3 release."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return Result(False, None, f"cannot read release {path}: {exc}")
    if not isinstance(document, dict):
        return Result(False, None, "release descriptor must be a JSON object")
    if document.get("schema_version") != 3 or not isinstance(document.get("package"), dict):
        return Result(False, None, "release descriptor must be a schema 3 package release")
    if "signature" in document:
        return Result(False, None, "release descriptor already carries a signature")
    return Result(True, document, None)


def write_signed(release: dict, fields: dict, path: Path) -> Result:
    """Write the signed descriptor using the build-rule-feed.py JSON layout."""
    release["signature"] = {
        "algorithm": "cosign-keyless-v1",
        "certificate": fields["certificate"],
        "value": fields["value"],
        "integrated_time_ms": fields["integrated"] * 1000,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
        # Self-check the artifact: a descriptor that does not round-trip would
        # silently break the feed client that parses it.
        written = json.loads(path.read_text(encoding="utf-8"))
        if written.get("signature") != release["signature"]:
            raise ValueError("written descriptor does not carry the embedded signature")
    except (OSError, ValueError) as exc:
        return Result(False, None, f"cannot write a sound signed release {path}: {exc}")
    return Result(True, path, None)


def main(argv: list | None = None) -> int:
    """Run the tool; returns the process exit code."""
    parser = build_parser()
    if argv is None and len(sys.argv) == 1:  # B1: no args -> help
        parser.print_help()
        return 2
    args = parser.parse_args(argv)
    bundle = load_bundle(Path(args.bundle))
    if not bundle.status:
        print(f"error: {bundle.error}", file=sys.stderr)
        return 1
    release = load_release(Path(args.release))
    if not release.status:
        print(f"error: {release.error}", file=sys.stderr)
        return 1
    signed = write_signed(release.output, bundle.output, Path(args.output))  # type: ignore[arg-type]
    if not signed.status:
        print(f"error: {signed.error}", file=sys.stderr)
        return 1
    print(f"Signed release descriptor written to {signed.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
