#!/usr/bin/env python3
"""Release automation for the Talon workspace (run by .github/workflows/release.yml).

Every merge to `main` that passes CI and changes a published crate becomes a
release: one version for the whole workspace, a `chore(release)` commit, a
`vX.Y.Z` tag and every `talahon-*` crate on crates.io.

    release.py bump [--notes FILE]   decide the next version, update Cargo.toml,
                                     Cargo.lock and CHANGELOG.md, commit and tag
                                     (nothing is pushed)
    release.py notes VERSION FILE    write the CHANGELOG section of VERSION
    release.py publish               publish every crate whose version is not on
                                     crates.io yet, dependencies first

The next version follows Conventional Commits over every commit since the last
tag: `type!:` or a `BREAKING CHANGE:` footer is a major release, `feat` a minor
one, anything else a patch. A version raised by hand in Cargo.toml (above the
last tag) is released as it is.

`bump` writes `version=`, `tag=` and `created=true|false` to $GITHUB_OUTPUT.
`publish` is idempotent: run it again to finish an interrupted release. It
waits out crates.io's rate limit for new crates (a handful at once, then one
every few minutes) until RELEASE_DEADLINE (Unix time) and fails after that.
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "Cargo.toml"
CHANGELOG = ROOT / "CHANGELOG.md"
RELEASE_PREFIX = "chore(release):"
# Paths whose changes end up in a published crate.
PUBLISHED_PATHS = ["crates", "Cargo.toml", "Cargo.lock", "README.md", "LICENSE"]
INDEX_URL = "https://index.crates.io"
USER_AGENT = "talahon-release (https://github.com/Liohtml/talahon)"
CONVENTIONAL = re.compile(r"^(?P<type>[a-zA-Z]+)(?:\([^)]*\))?(?P<bang>!)?:")
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(*args: str, capture: bool = True) -> str:
    out = subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=capture)
    return out.stdout.strip() if capture else ""


def git(*args: str) -> str:
    return run("git", *args)


def set_output(**values: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{k}={v}\n" for k, v in values.items())
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(lines)
    else:
        sys.stdout.write(lines)


def parse_version(v: str) -> tuple[int, int, int]:
    m = SEMVER.match(v)
    if not m:
        raise SystemExit(f"unsupported version {v!r} (expected MAJOR.MINOR.PATCH)")
    return int(m[1]), int(m[2]), int(m[3])


def workspace_version() -> str:
    return tomllib.loads(MANIFEST.read_text(encoding="utf-8"))["workspace"]["package"]["version"]


def last_tag() -> str | None:
    try:
        return git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*")
    except subprocess.CalledProcessError:
        return None


def tag_exists(tag: str) -> bool:
    return subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=ROOT, capture_output=True
    ).returncode == 0


def commits(rev_range: str, *extra: str) -> list[tuple[str, str]]:
    """(subject, body) of the commits in `rev_range`, release commits excluded."""
    raw = git("log", *extra, "--format=%s%x1f%b%x1e", rev_range)
    out = []
    for entry in raw.split("\x1e"):
        entry = entry.strip("\n")
        if not entry:
            continue
        subject, _, body = entry.partition("\x1f")
        if not subject.startswith(RELEASE_PREFIX):
            out.append((subject, body))
    return out


def bump_level(entries: list[tuple[str, str]]) -> str:
    level = "patch"
    for subject, body in entries:
        m = CONVENTIONAL.match(subject)
        if (m and m["bang"]) or re.search(r"^BREAKING[ -]CHANGE:", body, re.M):
            return "major"
        if m and m["type"].lower() == "feat":
            level = "minor"
    return level


def next_version(current: str, level: str) -> str:
    major, minor, patch = parse_version(current)
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def write_version(old: str, new: str) -> None:
    """Set workspace.package.version and the internal dependency requirements."""
    text = MANIFEST.read_text(encoding="utf-8")
    text, n = re.subn(
        r'(\[workspace\.package\]\nversion = )"[^"]+"', rf'\g<1>"{new}"', text, count=1
    )
    if n != 1:
        raise SystemExit("workspace.package.version not found in Cargo.toml")
    text, deps = re.subn(
        rf'^(talon-[a-z]+ = \{{ package = "talahon-[a-z]+", path = "[^"]+", version = )"{re.escape(old)}"',
        rf'\g<1>"{new}"',
        text,
        flags=re.M,
    )
    log(f"Cargo.toml: {old} -> {new} ({deps} internal dependencies)")
    MANIFEST.write_text(text, encoding="utf-8")
    run("cargo", "update", "--workspace", capture=False)


def changelog_section(version: str, entries: list[tuple[str, str]]) -> str:
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    lines = [f"## [{version}] - {today}", ""]
    seen = set()
    for subject, _ in entries:
        if subject.startswith("Merge ") or subject in seen:
            continue
        seen.add(subject)
        lines.append(f"- {subject}")
    return "\n".join(lines) + "\n"


def prepend_changelog(section: str) -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    marker = re.search(r"^## \[", text, re.M)
    pos = marker.start() if marker else len(text)
    CHANGELOG.write_text(text[:pos] + section + "\n" + text[pos:], encoding="utf-8")


def extract_notes(version: str) -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
    notes = m[1].strip() if m else ""
    return (notes or f"Talon v{version}") + "\n"


def cmd_bump(args: argparse.Namespace) -> None:
    version = workspace_version()
    tag = last_tag()

    if tag is None or (parse_version(version) > parse_version(tag[1:]) and not tag_exists(f"v{version}")):
        # First release, or a version raised by hand: release it as it is.
        new = version
        log(f"releasing v{new} as set in Cargo.toml (last tag: {tag or 'none'})")
        if tag is not None and f"## [{new}]" not in CHANGELOG.read_text(encoding="utf-8"):
            prepend_changelog(changelog_section(new, commits(f"{tag}..HEAD", "--first-parent")))
            git("add", "CHANGELOG.md")
            git("commit", "-m", f"{RELEASE_PREFIX} v{new} [skip ci]")
    else:
        if parse_version(version) < parse_version(tag[1:]):
            raise SystemExit(f"Cargo.toml version {version} is below the last tag {tag}")
        if not commits(f"{tag}..HEAD"):
            log(f"no commits since {tag}; nothing to release")
            set_output(created="false", version=version, tag=tag)
            return
        if not git("diff", "--name-only", tag, "HEAD", "--", *PUBLISHED_PATHS):
            log(f"nothing under {', '.join(PUBLISHED_PATHS)} changed since {tag}; nothing to release")
            set_output(created="false", version=version, tag=tag)
            return
        level = bump_level(commits(f"{tag}..HEAD"))
        new = next_version(tag[1:], level)
        log(f"{level} release: {tag} -> v{new}")
        write_version(version, new)
        prepend_changelog(changelog_section(new, commits(f"{tag}..HEAD", "--first-parent")))
        git("add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git("commit", "-m", f"{RELEASE_PREFIX} v{new} [skip ci]")

    git("tag", "-a", f"v{new}", "-m", f"Talon v{new}")
    if args.notes:
        Path(args.notes).write_text(extract_notes(new), encoding="utf-8")
    set_output(created="true", version=new, tag=f"v{new}")


def cmd_notes(args: argparse.Namespace) -> None:
    Path(args.file).write_text(extract_notes(args.version), encoding="utf-8")


# --- publish ---------------------------------------------------------------


def publishable_packages() -> list[dict]:
    """Workspace packages published to crates.io, dependencies first."""
    meta = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"))
    pkgs = {p["name"]: p for p in meta["packages"] if p["publish"] is None or "crates-io" in p["publish"]}
    order: list[str] = []
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in order:
            return
        if name in visiting:
            raise SystemExit(f"dependency cycle through {name}")
        visiting.add(name)
        # Dev-dependencies too: crates.io needs every listed dependency to exist.
        for dep in pkgs[name]["dependencies"]:
            if dep["name"] in pkgs and dep["name"] != name:
                visit(dep["name"])
        visiting.discard(name)
        order.append(name)

    for name in sorted(pkgs):
        visit(name)
    return [pkgs[n] for n in order]


def index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def published_versions(name: str) -> set[str]:
    req = urllib.request.Request(f"{INDEX_URL}/{index_path(name)}", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        if err.code in (403, 404):
            return set()
        raise
    return {json.loads(line)["vers"] for line in body.splitlines() if line.strip()}


def retry_after(output: str) -> float | None:
    """Seconds to wait if crates.io rate-limited the upload, else None."""
    if "429" not in output and "Too Many Requests" not in output and "too many" not in output:
        return None
    m = re.search(r"try again after (.+? GMT)", output)
    if m:
        try:
            when = email.utils.parsedate_to_datetime(m[1])
            return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds()) + 15
        except (TypeError, ValueError):
            pass
    return 600.0


def cmd_publish(_: argparse.Namespace) -> None:
    if not os.environ.get("CARGO_REGISTRY_TOKEN"):
        print(
            "::warning title=crates.io::CARGO_REGISTRY_TOKEN is not set; nothing was published. "
            "Add it to the CRATES environment, then re-run the Release workflow."
        )
        return
    deadline = float(os.environ.get("RELEASE_DEADLINE", time.time() + 3 * 3600))
    pending = [p for p in publishable_packages() if p["version"] not in published_versions(p["name"])]
    if not pending:
        log("every crate is already on crates.io")
        return
    log("to publish: " + ", ".join(f"{p['name']} {p['version']}" for p in pending))

    for pkg in pending:
        name, version = pkg["name"], pkg["version"]
        resolve_retries = 0
        while True:
            log(f"publishing {name} {version}")
            proc = subprocess.run(
                ["cargo", "publish", "--locked", "--no-verify", "-p", name],
                cwd=ROOT, text=True, capture_output=True,
            )
            output = proc.stdout + proc.stderr
            sys.stderr.write(output)
            if proc.returncode == 0:
                break
            if "already exists" in output:
                log(f"{name} {version} is already on crates.io")
                break
            wait = retry_after(output)
            if wait is None and resolve_retries < 5 and (
                "failed to select a version" in output or "no matching package named" in output
            ):
                # A dependency published a moment ago is not visible in the index yet.
                resolve_retries += 1
                wait = 30.0
            if wait is None:
                raise SystemExit(f"publishing {name} {version} failed")
            if time.time() + wait > deadline:
                raise SystemExit(
                    f"crates.io asks to wait {wait / 60:.0f} min, past this run's deadline; "
                    "re-run the Release workflow to publish the remaining crates"
                )
            log(f"waiting {wait / 60:.1f} min before retrying {name}")
            time.sleep(wait)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    bump = sub.add_parser("bump", help="decide, commit and tag the next version")
    bump.add_argument("--notes", help="write the release notes to this file")
    bump.set_defaults(func=cmd_bump)
    notes = sub.add_parser("notes", help="write the CHANGELOG section of a version")
    notes.add_argument("version")
    notes.add_argument("file")
    notes.set_defaults(func=cmd_notes)
    publish = sub.add_parser("publish", help="publish crates missing on crates.io")
    publish.set_defaults(func=cmd_publish)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
