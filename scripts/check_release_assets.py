#!/usr/bin/env python3
"""Release prerequisites of the AnixOps Agent packages (H20, O1 installer).

Each linux release zip carries the Agent (a regular executable at the root of
the zip) and neither gost nor the experimental anixops relay (both removed:
the network model replaced them), and the release publishes SHA256SUMS and a detached signature
(`<asset>.sig`: base64 of the raw Ed25519 signature by the official AnixOps
release key over the asset's exact bytes, as anix-control signs
agent-install.sh) for every package and for SHA256SUMS.

  check_release_assets.py zip --zip FILE
  check_release_assets.py workflow [--file .github/workflows/release.yml]
  check_release_assets.py --self-test
"""

from __future__ import annotations

import argparse
import io
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

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


def check_zip(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        regular_member(archive, "anix-agent")
        for removed in ("gost", "anixops-relay"):
            if removed in archive.namelist():
                raise CheckError(f"the package still holds {removed}, which was removed")


def check_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    required = {
        f"ANIXOPS_OFFICIAL_PUBLIC_KEY: '{OFFICIAL_PUBLIC_KEY}'": "the official release key",
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
    executable = stat.S_IFREG | 0o755
    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "good.zip"
        make_zip(good, {"anix-agent": (b"agent", executable)})
        check_zip(good)
        cases = {
            "gost": {"anix-agent": (b"agent", executable), "gost": (b"gost", executable)},
            "relay": {"anix-agent": (b"agent", executable), "anixops-relay": (b"relay", executable)},
            "no agent": {"README.md": (b"readme", stat.S_IFREG | 0o644)},
            "agent link": {"anix-agent": (b"agent", stat.S_IFLNK | 0o777)},
            "agent not executable": {"anix-agent": (b"agent", stat.S_IFREG | 0o644)},
        }
        for name, members in cases.items():
            bad = Path(tmp) / "bad.zip"
            make_zip(bad, members)
            try:
                check_zip(bad)
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
    workflow_parser = sub.add_parser("workflow")
    workflow_parser.add_argument("--file", type=Path, default=WORKFLOW)
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
        elif args.command == "zip":
            check_zip(args.zip)
            print(f"{args.zip.name}: anix-agent is in the package")
        elif args.command == "workflow":
            check_workflow(args.file)
            print(f"{args.file.name}: the package build, SHA256SUMS and signatures are in place")
        else:
            parser.print_help()
            return 2
    except CheckError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
