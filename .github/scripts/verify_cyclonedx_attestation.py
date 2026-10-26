#!/usr/bin/env python3
"""Check Cosign-verified DSSE output is this exact SBOM and image subject."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"
IN_TOTO_TYPES = {
    "https://in-toto.io/Statement/v0.1",
    "https://in-toto.io/Statement/v1",
}


def matching_verified_statement(
    lines: list[str], sbom: dict[str, Any], image_digest: str
) -> bool:
    """Require one Cosign-verified statement with exact predicate and digest."""
    algorithm, separator, digest = image_digest.partition(":")
    if not separator or algorithm != "sha256" or len(digest) != 64:
        return False
    for line in lines:
        try:
            envelope = json.loads(line)
            encoded_payload = envelope.get("payload")
            if not isinstance(encoded_payload, str):
                continue
            statement = json.loads(base64.b64decode(encoded_payload, validate=True))
            if statement.get("_type") not in IN_TOTO_TYPES:
                continue
            if statement.get("predicateType") != CYCLONEDX_PREDICATE:
                continue
            subjects = statement.get("subject")
            if not isinstance(subjects, list) or len(subjects) != 1:
                continue
            subject_digest = subjects[0].get("digest")
            if subject_digest != {"sha256": digest}:
                continue
            if statement.get("predicate") != sbom:
                continue
            return True
        except (ValueError, TypeError, AttributeError, UnicodeDecodeError):
            continue
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation-file", type=Path, required=True)
    parser.add_argument("--sbom-file", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    try:
        sbom = json.loads(args.sbom_file.read_text(encoding="utf-8"))
        lines = args.attestation_file.read_text(encoding="utf-8").splitlines()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read verification inputs: {exc}", file=sys.stderr)
        return 2
    if not matching_verified_statement(lines, sbom, args.image_digest):
        print(
            "verified Cosign output did not contain the exact CycloneDX predicate "
            "and immutable image subject",
            file=sys.stderr,
        )
        return 1
    print(f"verified CycloneDX predicate is bound to {args.image_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
