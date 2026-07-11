"""
Git repository posture collector.

Usage:
    python git-posture.py --evidence-root ./audit-run [--repo-roots ~/code,~/repos] [--allow-gh] [--dry-run]

Scans git repos for .env in history, hook presence, .gitignore coverage,
optional branch protection via gh CLI, and large blobs.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import (
    add_base_args,
    compute_scope_hash,
    default_repo_roots,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    redact_scope_label,
    validate_evidence_root,
)

__version__ = "1.0.0"

COLLECTOR = "git-posture"
LARGE_BLOB_BYTES = 10 * 1024 * 1024

SECRET_GITIGNORE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "credentials.json",
    "secrets.json",
]


def find_git_repos(roots: list[Path]) -> list[Path]:
    repos: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists():
            continue
        git_dir = root / ".git"
        if git_dir.exists():
            key = str(root.resolve())
            if key not in seen:
                seen.add(key)
                repos.append(root)
            continue
        for path in root.rglob(".git"):
            if path.is_dir() and path.name == ".git":
                repo = path.parent
                key = str(repo.resolve())
                if key not in seen:
                    seen.add(key)
                    repos.append(repo)
    return sorted(repos, key=lambda p: str(p))


def run_git(repo: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_env_in_history(repo: Path) -> bool:
    result = run_git(
        repo,
        "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A",
    )
    if not result or result.returncode != 0:
        return False
    env_re = re.compile(r"(^|/)\.env($|\.)")
    for line in result.stdout.splitlines():
        if env_re.search(line.strip()):
            return True
    return False


def check_pre_commit(repo: Path) -> bool:
    hook = repo / ".git" / "hooks" / "pre-commit"
    if hook.exists() and hook.stat().st_size > 0:
        return True
    if (repo / ".pre-commit-config.yaml").exists():
        return True
    return False


def check_gitignore(repo: Path) -> tuple[bool, list[str]]:
    gi = repo / ".gitignore"
    if not gi.exists():
        return False, SECRET_GITIGNORE_PATTERNS
    try:
        content = gi.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, SECRET_GITIGNORE_PATTERNS
    missing = []
    for pattern in SECRET_GITIGNORE_PATTERNS:
        if pattern not in content and pattern.replace("*", "") not in content:
            missing.append(pattern)
    return len(missing) == 0, missing


def check_large_blobs(repo: Path) -> list[tuple[str, int]]:
    large: list[tuple[str, int]] = []
    rev = run_git(repo, "rev-list", "--objects", "--all")
    if not rev or rev.returncode != 0 or not rev.stdout.strip():
        return large
    try:
        proc = subprocess.run(
            [
                "git", "-C", str(repo), "cat-file",
                "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)",
            ],
            input=rev.stdout,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return large
    if proc.returncode != 0:
        return large
    for line in proc.stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        obj_type, _obj_name, size_str = parts[0], parts[1], parts[2]
        if obj_type != "blob":
            continue
        try:
            size = int(size_str)
        except ValueError:
            continue
        if size > LARGE_BLOB_BYTES:
            name = parts[3] if len(parts) > 3 else "unknown"
            large.append((name, size))
    return large[:20]


def gh_available() -> bool:
    return shutil.which("gh") is not None


def parse_gh_repo(remote_url: str) -> tuple[str, str] | None:
    match = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", remote_url)
    if not match:
        return None
    return match.group(1), match.group(2).replace(".git", "")


def check_branch_protection(repo: Path) -> bool | None:
    if not gh_available():
        return None
    remote = run_git(repo, "remote", "get-url", "origin")
    if not remote or remote.returncode != 0:
        return None
    parsed = parse_gh_repo(remote.stdout.strip())
    if not parsed:
        return None
    owner, repo_name = parsed
    branch = run_git(repo, "symbolic-ref", "--short", "HEAD")
    if not branch or branch.returncode != 0:
        return None
    default_branch = branch.stdout.strip()
    try:
        proc = subprocess.run(
            ["gh", "api", f"repos/{owner}/{repo_name}/branches/{default_branch}/protection"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.returncode == 0


def repo_display_name(repo: Path) -> str:
    return repo.name or "unknown"


def collect(repo_roots: list[Path], allow_gh: bool) -> dict:
    repos = find_git_repos(repo_roots)
    scope_hash = compute_scope_hash(str(r.resolve()) for r in repos)
    platform_detected = bool(repos)

    envelope = make_envelope(
        COLLECTOR,
        __version__,
        scope_hash,
        platform_detected=platform_detected,
    )

    if not platform_detected:
        reason = "no_repo_roots" if not repo_roots else "no_repos_in_roots"
        envelope["findings"] = [
            make_finding(
                f"git.scan.{reason}",
                "low",
                "Git Posture",
                (
                    "No default repo roots exist under the user profile; pass --repo-roots "
                    "(or -RepoRoots via aiscan.ps1) to scan your code directories"
                    if reason == "no_repo_roots"
                    else "Repo roots exist but contain no git repositories"
                ),
                tags=["env_read"],
            )
        ]
        envelope["summary"] = {"repos_scanned": 0, "roots_checked": len(repo_roots)}
        return envelope

    rules: list[dict] = []
    findings: list[dict] = []
    env_hits = 0
    no_hooks = 0
    no_protection = 0
    large_blob_count = 0

    for repo in repos:
        repo_label = repo_display_name(repo)
        repo_sample = redact_scope_label(repo_label, "project")
        env_in_history = check_env_in_history(repo)
        has_hooks = check_pre_commit(repo)
        gi_ok, gi_missing = check_gitignore(repo)
        large_blobs = check_large_blobs(repo)
        protection = check_branch_protection(repo) if allow_gh else None

        rules.append(
            make_rule(
                "git",
                "project",
                repo_label,
                "other",
                f"pre_commit={'yes' if has_hooks else 'no'}",
                "allow" if has_hooks else "deny",
                command_or_tool="pre-commit",
                risk="low" if has_hooks else "medium",
                exposure_category="Git Posture",
            )
        )
        rules.append(
            make_rule(
                "git",
                "project",
                repo_label,
                "other",
                f"gitignore_secrets={'ok' if gi_ok else 'gaps'}",
                "allow" if gi_ok else "ask",
                command_or_tool="gitignore",
                risk="low" if gi_ok else "medium",
                exposure_category="Git Posture",
            )
        )

        if env_in_history:
            env_hits += 1
            findings.append(
                make_finding(
                    "git.env.in_history",
                    "critical",
                    "Git Posture",
                    ".env file found in git commit history",
                    sample_redacted=repo_sample,
                    tags=["env_read"],
                )
            )
        if not has_hooks:
            no_hooks += 1
            findings.append(
                make_finding(
                    "git.hooks.missing",
                    "medium",
                    "Git Posture",
                    "Repository has no pre-commit hooks configured",
                    sample_redacted=repo_sample,
                    tags=["pre_commit_missing"],
                )
            )
        if allow_gh and protection is False:
            no_protection += 1
            findings.append(
                make_finding(
                    "git.branch.no_protection",
                    "medium",
                    "Git Posture",
                    "Default branch lacks GitHub branch protection",
                    sample_redacted=repo_sample,
                    tags=["gh_token_present"],
                )
            )
        for blob_name, size in large_blobs:
            large_blob_count += 1
            findings.append(
                make_finding(
                    "git.blob.large",
                    "low",
                    "Git Posture",
                    f"Large blob ({size // (1024*1024)}MB) in repository history",
                    sample_redacted=blob_name[:40],
                    tags=["history_retention"],
                )
            )

    envelope["rules"] = rules
    envelope["findings"] = findings
    envelope["summary"] = {
        "repos_scanned": len(repos),
        "env_in_history": env_hits,
        "no_pre_commit": no_hooks,
        "no_branch_protection": no_protection,
        "large_blobs": large_blob_count,
        "gh_checked": allow_gh and gh_available(),
    }
    return envelope


def main() -> None:
    parser = argparse.ArgumentParser(description="Git repository posture collector")
    add_base_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo scan roots (default: common code dirs under "
        "the user profile, e.g. ~/repos, ~/code, ~/projects, ~/cursor-projects, "
        "~/Documents/GitHub; see common.DEFAULT_REPO_ROOT_NAMES)",
    )
    parser.add_argument(
        "--allow-gh",
        action="store_true",
        help="Use gh CLI to check branch protection (requires auth)",
    )
    args = parser.parse_args()
    evidence_root = validate_evidence_root(args.evidence_root)

    if args.repo_roots:
        repo_roots = [Path(p.strip()) for p in args.repo_roots.split(",") if p.strip()]
    else:
        repo_roots = default_repo_roots()

    envelope = collect(repo_roots, args.allow_gh)
    if not envelope["platform_detected"]:
        finish_collector(envelope, evidence_root, dry_run=args.dry_run)
        sys.exit(2)

    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0)


if __name__ == "__main__":
    main()
