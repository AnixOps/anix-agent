#!/usr/bin/env python3
"""Require an Agent release tag to match every shipped version surface."""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path


TAG_PATTERN = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-(?:alpha|beta|rc)(?:\.[0-9]+)?)?)$")


def require_pattern(path: Path, pattern: str, expected: str, label: str) -> None:
    content = path.read_text(encoding="utf-8")
    match = re.search(pattern, content, re.MULTILINE)
    actual = match.group(1) if match else "<missing>"
    if actual != expected:
        raise ValueError(f"{label} version mismatch: expected {expected}, found {actual}")


def check_release_version(repo_root: Path, tag: str) -> str:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ValueError(f"unsupported release tag: {tag}")
    version = match.group("version")
    require_pattern(repo_root / "cmd/version.go", r'^\s*(?:var\s+)?version\s*=\s*"v([^"]+)"', version, "CLI")
    require_pattern(repo_root / "api/panel/version.go", r'^var Version = "([^"]+)"', version, "panel")
    require_pattern(repo_root / "Dockerfile", r'^ARG VERSION=v([^\s]+)', version, "Docker build")
    require_pattern(repo_root / "README.md", r'^`v([^`]+)` 提供 AnixOps 官方签名软件包', version, "README preview")
    require_pattern(repo_root / "docs/INSTALL.md", r'^export VERSION=v([^\s]+)', version, "install guide")
    require_pattern(repo_root / "docs/ANIX_AGENT_MIGRATION.md", r'^export VERSION=v([^\s]+)', version, "migration guide")
    require_pattern(repo_root / "CHANGELOG.md", r'^## ([^\s]+) - \d{4}-\d{2}-\d{2}$', version, "changelog")
    return version


def write_fixture(root: Path, version: str) -> None:
    files = {
        "cmd/version.go": f'package cmd\nvar version = "v{version}"\n',
        "api/panel/version.go": f'package panel\nvar Version = "{version}"\n',
        "Dockerfile": f"ARG VERSION=v{version}\n",
        "README.md": f"`v{version}` 提供 AnixOps 官方签名软件包\n",
        "docs/INSTALL.md": f"export VERSION=v{version}\n",
        "docs/ANIX_AGENT_MIGRATION.md": f"export VERSION=v{version}\n",
        "CHANGELOG.md": f"# Changelog\n\n## {version} - 2026-07-17\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def self_test() -> None:
    version = "3.1.0-alpha.2"
    with tempfile.TemporaryDirectory(prefix="anix-agent-release-version-") as temporary:
        root = Path(temporary)
        write_fixture(root, version)
        assert check_release_version(root, f"v{version}") == version

        dockerfile = root / "Dockerfile"
        dockerfile.write_text("ARG VERSION=v3.1.0-alpha.3\n", encoding="utf-8")
        try:
            check_release_version(root, f"v{version}")
        except ValueError as error:
            assert "Docker build version mismatch" in str(error)
        else:
            raise AssertionError("Docker version mismatch was accepted")

        try:
            check_release_version(root, "v4")
        except ValueError as error:
            assert "unsupported release tag" in str(error)
        else:
            raise AssertionError("invalid release tag was accepted")
    print("Agent release version self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Release tag, including the leading v")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.tag:
        raise SystemExit("--tag is required")
    version = check_release_version(args.repo_root.resolve(), args.tag)
    print(f"Agent release version surfaces match {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
