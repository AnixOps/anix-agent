#!/usr/bin/env python3
"""Release prerequisites of the AnixOps Agent packages (H20, O1 installer).

Each linux release zip carries the Agent and the pinned gost v3 release
(`gost`, a regular executable file at the root of the zip, checked by
SHA-256), and the release publishes SHA256SUMS and a detached signature
(`<asset>.sig`: base64 of the raw Ed25519 signature by the official AnixOps
release key over the asset's exact bytes, as anix-control signs
agent-install.sh) for every package and for SHA256SUMS.

  check_release_assets.py zip --zip FILE --gost-sha256 HEX
  check_release_assets.py workflow [--file .github/workflows/release.yml]
  check_release_assets.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

GOST_VERSION = "3.2.6"
# anix-control .github/workflows/ci.yml pins the same release (H20).
GOST_SHA256 = {
    "GOST_LINUX_AMD64_ARCHIVE_SHA256": "b39037b0380ea001fb3c0c28441c2e10bfc694f90682739a65b53e55dce5238b",
    "GOST_LINUX_AMD64_BINARY_SHA256": "a2aea24efb4597b5f57b35b8e1bbcc59f439b80723854d4371f6828b46682ffb",
    "GOST_LINUX_ARM64_ARCHIVE_SHA256": "f674c8f4a033dc1dfd4f0d5e9602fbe5b0d0f81307bf3794f44b5b5d6d622eae",
    "GOST_LINUX_ARM64_BINARY_SHA256": "343c3e003996ca0437b9cc47dd1500cd0475ba09f5a5f17e50851854e06a1ca7",
}
# plugins.official_public_key of anix-control (config/config.prod.yaml) and
# OFFICIAL_PUBLIC_KEY of its install.sh.
OFFICIAL_PUBLIC_KEY = "jW26nr2tbthASoeq6RmIpx8Ah+uhPNIv9V1ewRVb1VE="
PACKAGES = ("anix-agent-linux-64.zip", "anix-agent-linux-arm64-v8a.zip")


class CheckError(Exception):
    pass


def regular_member(archive: zipfile.ZipFile, name: str) -> zipfile.ZipInfo:
    try:
        info = archive.getinfo(name)
    except KeyError as exc:
        raise CheckError(f"the package has no {name}") from exc
    mode = info.external_attr >> 16
    if mode and not stat.S_ISREG(mode):
        raise CheckError(f"{name} in the package is not a regular file")
    if mode and not mode & 0o111:
        raise CheckError(f"{name} in the package is not executable")
    return info


def check_zip(path: Path, gost_sha256: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", gost_sha256):
        raise CheckError("--gost-sha256 must be a lowercase SHA-256")
    with zipfile.ZipFile(path) as archive:
        regular_member(archive, "anix-agent")
        regular_member(archive, "gost")
        digest = hashlib.sha256(archive.read("gost")).hexdigest()
    if digest != gost_sha256:
        raise CheckError(f"gost in the package has SHA-256 {digest}, not the pinned {gost_sha256}")


def check_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    required = {
        f"GOST_VERSION: '{GOST_VERSION}'": "the pinned gost version",
        f"ANIXOPS_OFFICIAL_PUBLIC_KEY: '{OFFICIAL_PUBLIC_KEY}'": "the official release key",
        "install -m 0755 \"${stage}/gost\" build_assets/gost": "gost bundled in the package",
        "sha256sum --check --strict": "the gost checksum checks",
        "scripts/check_release_assets.py zip": "the package check in the build",
        "secrets.ANIXOPS_PLUGIN_SIGNING_PRIVATE_KEY": "the signing key secret",
        "secrets.ANIXOPS_PLUGIN_OFFICIAL_PUBLIC_KEY": "the official key secret",
        "sha256sum \"${packages[@]}\" >SHA256SUMS": "SHA256SUMS",
        "openssl pkeyutl -sign -inkey \"${key_file}\" -rawin": "raw Ed25519 signatures",
        "base64 -w0": "base64 signatures",
        "openssl pkeyutl -verify -pubin -keyform DER": "the signature verification",
        "dist/SHA256SUMS\n": "SHA256SUMS in the release",
        "dist/SHA256SUMS.sig": "SHA256SUMS.sig in the release",
    }
    for key, value in GOST_SHA256.items():
        required[f"{key}: '{value}'"] = f"the pinned {key}"
    for package in PACKAGES:
        required[f"dist/{package}\n"] = f"{package} in the release"
        required[f"dist/{package}.dgst"] = f"{package}.dgst in the release"
        required[f"dist/{package}.sig"] = f"{package}.sig in the release"
    missing = [what for needle, what in required.items() if needle not in text]
    if missing:
        raise CheckError(f"{path.name} lacks: " + "; ".join(missing))


def make_zip(path: Path, members: dict[str, tuple[bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, (data, mode) in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)


def self_test() -> None:
    gost = b"pinned gost"
    digest = hashlib.sha256(gost).hexdigest()
    executable = stat.S_IFREG | 0o755
    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "good.zip"
        make_zip(good, {"anix-agent": (b"agent", executable), "gost": (gost, executable)})
        check_zip(good, digest)
        cases = {
            "no gost": {"anix-agent": (b"agent", executable)},
            "other gost": {"anix-agent": (b"agent", executable), "gost": (b"other", executable)},
            "gost link": {"anix-agent": (b"agent", executable), "gost": (b"target", stat.S_IFLNK | 0o777)},
            "gost not executable": {"anix-agent": (b"agent", executable), "gost": (gost, stat.S_IFREG | 0o644)},
            "no agent": {"gost": (gost, executable)},
        }
        for name, members in cases.items():
            bad = Path(tmp) / "bad.zip"
            make_zip(bad, members)
            try:
                check_zip(bad, digest)
            except CheckError:
                continue
            raise CheckError(f"self-test: a package with {name} passed")
        broken = Path(tmp) / "release.yml"
        broken.write_text(WORKFLOW.read_text(encoding="utf-8").replace("dist/SHA256SUMS.sig", ""), encoding="utf-8")
        try:
            check_workflow(broken)
        except CheckError:
            pass
        else:
            raise CheckError("self-test: a workflow without SHA256SUMS.sig passed")
    check_workflow(WORKFLOW)
    print("release asset checks: self-test passed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    zip_parser = sub.add_parser("zip")
    zip_parser.add_argument("--zip", required=True, type=Path)
    zip_parser.add_argument("--gost-sha256", required=True)
    workflow_parser = sub.add_parser("workflow")
    workflow_parser.add_argument("--file", type=Path, default=WORKFLOW)
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
        elif args.command == "zip":
            check_zip(args.zip, args.gost_sha256)
            print(f"{args.zip.name}: anix-agent and the pinned gost {GOST_VERSION} are in the package")
        elif args.command == "workflow":
            check_workflow(args.file)
            print(f"{args.file.name}: gost bundling, SHA256SUMS and signatures are in place")
        else:
            parser.print_help()
            return 2
    except CheckError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
