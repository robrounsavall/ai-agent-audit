"""
Git repository posture collector.

Usage:
    python git-posture.py --evidence-root ./audit-run [--repo-roots ~/code,~/repos] [--allow-gh] [--dry-run]

Scans git repos for .env in history, hook presence, .gitignore coverage,
optional branch protection via gh CLI, and large blobs.

Git commands run with lazy fetch disabled, so a partial clone cannot pull
missing objects from the network. Those repos are reported as a coverage gap.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from common import (
    add_base_args,
    clip_sanitized,
    compute_scope_hash,
    default_repo_roots,
    finish_collector,
    make_envelope,
    make_finding,
    make_rule,
    redact_scope_label,
    validate_evidence_root,
)

__version__ = "1.1.0"

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

# A filename each pattern must ignore. Matching is against gitignore rules,
# not a substring of the file, so a comment or a "!pattern" line does not count.
_GITIGNORE_PROBE_NAMES = {
    ".env": ".env",
    ".env.*": ".env.local",
    "*.pem": "cert.pem",
    "*.key": "cert.key",
    "id_rsa": "id_rsa",
    "credentials.json": "credentials.json",
    "secrets.json": "secrets.json",
}

# Committed example files are not a live environment file.
_ENV_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")


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


def git_local_env() -> dict[str, str]:
    """Environment for every git subprocess.

    GIT_NO_LAZY_FETCH stops a partial clone from downloading missing objects.
    GIT_TERMINAL_PROMPT and an empty GIT_ASKPASS stop git from prompting for
    credentials, which would also reach the network.
    """
    env = dict(os.environ)
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    return env


def run_git(
    repo: Path,
    *args: str,
    timeout: int = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=git_local_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _is_env_history_path(line: str) -> bool:
    """True for a committed .env or .env.<name>, not an example or template."""
    text = line.strip().replace("\\", "/")
    if not text or text.endswith("/"):
        return False
    base = text.split("/")[-1]
    if base != ".env" and not base.startswith(".env."):
        return False
    return not any(base.endswith(suffix) for suffix in _ENV_EXAMPLE_SUFFIXES)


def is_partial_clone(repo: Path) -> bool:
    """True when git would otherwise fetch missing objects from a promisor."""
    result = run_git(repo, "config", "--get", "extensions.partialclone")
    return bool(result and result.returncode == 0 and result.stdout.strip())


def check_env_in_history(repo: Path) -> bool:
    result = run_git(
        repo,
        "log", "--all", "--pretty=format:", "--name-only", "--diff-filter=A",
    )
    if not result or result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        if _is_env_history_path(line):
            return True
    return False


def check_pre_commit(repo: Path) -> bool:
    hook = repo / ".git" / "hooks" / "pre-commit"
    if hook.exists() and hook.stat().st_size > 0:
        return True
    if (repo / ".pre-commit-config.yaml").exists():
        return True
    return False


def _gitignore_rule_matches(pattern: str, name: str) -> bool:
    """True when one gitignore pattern matches a basename."""
    pat = pattern.strip()
    if pat.endswith("/"):
        pat = pat[:-1]
    while pat.startswith("/"):
        pat = pat[1:]
    while pat.startswith("**/"):
        pat = pat[3:]
    if not pat:
        return False
    base = name.replace("\\", "/").split("/")[-1]
    return fnmatch.fnmatch(base, pat)


def _gitignore_covers(content: str, name: str) -> bool:
    """Last matching rule wins. Comments and blank lines are not rules."""
    covered = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
            if not line:
                continue
        if _gitignore_rule_matches(line, name):
            covered = not negated
    return covered


def check_gitignore(repo: Path) -> tuple[bool, list[str]]:
    gi = repo / ".gitignore"
    if not gi.exists():
        return False, list(SECRET_GITIGNORE_PATTERNS)
    try:
        content = gi.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, list(SECRET_GITIGNORE_PATTERNS)
    missing = [
        pattern
        for pattern in SECRET_GITIGNORE_PATTERNS
        if not _gitignore_covers(content, _GITIGNORE_PROBE_NAMES[pattern])
    ]
    return len(missing) == 0, missing


def check_large_blobs(repo: Path) -> list[tuple[str, int]]:
    large: list[tuple[str, int]] = []
    rev = run_git(repo, "rev-list", "--objects", "--all")
    if not rev or rev.returncode != 0 or not rev.stdout.strip():
        return large
    proc = run_git(
        repo,
        "cat-file",
        "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)",
        input_text=rev.stdout,
    )
    if not proc or proc.returncode != 0:
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


def _count_label(count: int, singular: str) -> str:
    noun = singular if count == 1 else f"{singular}s"
    return f"{count} {noun}"


def _sample_list(labels: list[str], limit: int = 5) -> str:
    filtered = [label for label in labels if label]
    shown = filtered[:limit]
    text = ", ".join(shown)
    extra = len(filtered) - len(shown)
    if extra > 0:
        text += f" (+{extra} more)"
    return text


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
    env_hits = 0
    no_hooks = 0
    no_protection = 0
    large_blob_count = 0
    env_samples: list[str] = []
    hook_samples: list[str] = []
    protection_samples: list[str] = []
    blob_samples: list[str] = []
    largest_blob = 0
    partial_clones = 0

    for repo in repos:
        if is_partial_clone(repo):
            partial_clones += 1
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
            env_samples.append(repo_sample)
        if not has_hooks:
            no_hooks += 1
            hook_samples.append(repo_sample)
        if allow_gh and protection is False:
            no_protection += 1
            protection_samples.append(repo_sample)
        for blob_name, size in large_blobs:
            large_blob_count += 1
            if size > largest_blob:
                largest_blob = size
            blob_samples.append(
                f"{size // (1024 * 1024)}MB {clip_sanitized(blob_name, 40)}"
            )

    # One finding per check. Repeating the same title once per repo made the
    # severity counts and the top of the report list the same issue many times.
    findings: list[dict] = []
    if env_hits:
        findings.append(
            make_finding(
                "git.env.in_history",
                "critical",
                "Git Posture",
                f".env file found in git commit history ({_count_label(env_hits, 'repo')})",
                evidence_count=env_hits,
                sample_redacted=_sample_list(env_samples),
                tags=["env_read"],
            )
        )
    if no_hooks:
        findings.append(
            make_finding(
                "git.hooks.missing",
                "medium",
                "Git Posture",
                f"Repository has no pre-commit hooks configured ({_count_label(no_hooks, 'repo')})",
                evidence_count=no_hooks,
                sample_redacted=_sample_list(hook_samples),
                tags=["pre_commit_missing"],
            )
        )
    if no_protection:
        findings.append(
            make_finding(
                "git.branch.no_protection",
                "medium",
                "Git Posture",
                f"Default branch lacks GitHub branch protection ({_count_label(no_protection, 'repo')})",
                evidence_count=no_protection,
                sample_redacted=_sample_list(protection_samples),
                tags=["gh_token_present"],
            )
        )
    if large_blob_count:
        largest_mb = largest_blob // (1024 * 1024)
        findings.append(
            make_finding(
                "git.blob.large",
                "low",
                "Git Posture",
                (
                    f"Large blob in repository history "
                    f"({_count_label(large_blob_count, 'blob')}, largest {largest_mb}MB)"
                ),
                evidence_count=large_blob_count,
                sample_redacted=_sample_list(blob_samples),
                tags=["history_retention"],
            )
        )

    if partial_clones:
        noun = "clone" if partial_clones == 1 else "clones"
        findings.append(
            make_finding(
                "git.partial_clone",
                "low",
                "Git Posture",
                f"{partial_clones} partial {noun} scanned without fetching missing git objects",
                evidence_count=partial_clones,
                tags=["coverage_gap"],
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
        "partial_clones": partial_clones,
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
