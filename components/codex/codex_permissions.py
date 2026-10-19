"""Offline inventory of Codex permission files; never execute policy code."""
from __future__ import annotations

import ast
import io
import os
import re
import tokenize
from pathlib import Path

from common import clip_sanitized, default_repo_roots, make_finding, make_rule, sanitize_text
from configfmt import MAX_CONFIG_BYTES, load_jsonc, load_toml

INTERPRETERS = {"powershell", "pwsh", "cmd", "bash", "sh", "zsh", "python", "python3",
                "py", "node", "deno", "ruby", "perl", "wsl"}
EXEC_FLAGS = {"-c", "-lc", "/c", "-command", "-encodedcommand", "-e", "-file", "-"}
DECISION_MAP = {"allow": "allow", "prompt": "ask", "forbidden": "deny"}
SEVERITY_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low"}


def evaluate_permission_keys(data, *, layer_label="user config.toml"):
    data = data if isinstance(data, dict) else {}
    findings = []
    profile = layer_label.startswith("profile ")
    prefix = (f"Codex profile {sanitize_text(layer_label[8:])}: " if profile else
              "Codex project config: " if layer_label.startswith("project") else
              "Codex managed defaults: " if layer_label.startswith("managed") else "")

    def add(fid, severity, title, sample=""):
        if profile:
            severity = SEVERITY_DOWNGRADE.get(severity, severity)
        findings.append(make_finding(fid, severity, "General Tooling", prefix + title, sample_redacted=sample))

    selected = data.get("default_permissions", "unset")
    selected = selected if isinstance(selected, str) else "unset"
    profiles = data.get("permissions", {})
    profiles = profiles if isinstance(profiles, dict) else {}
    if selected == ":danger-full-access":
        add("codex.profile.full_access" if profile else "codex.permissions.full_access", "critical",
            "Codex default permissions grant full access", "full access selected" if profile else "default_permissions=:danger-full-access")
    apps = data.get("apps", {})
    reviewers = [data.get("approvals_reviewer")]
    if isinstance(apps, dict):
        reviewers.extend(v.get("approvals_reviewer") for v in apps.values() if isinstance(v, dict))
    if "auto_review" in reviewers:
        add("codex.approval.auto_review", "medium", "Codex approvals are reviewed by the auto_review agent, not you")
    policy = data.get("approval_policy")
    granular = policy.get("granular", policy) if isinstance(policy, dict) else {}
    if policy == "never" or (isinstance(granular, dict) and any(
            granular.get(k) is False for k in ("request_permissions", "sandbox_approval"))):
        add("codex.approval.never", "critical", "Codex approval policy disables permission gate")

    def root_write(fs):
        if not isinstance(fs, dict):
            return False
        for key, value in fs.items():
            root = key in ("/", ":root", "~", "**", "/**") or re.fullmatch(r"[A-Za-z]:[\\/]?", key)
            if root and (value == "write" or isinstance(value, dict) and "write" in value.values()):
                return True
            if isinstance(value, dict) and root_write(value):
                return True
        return False

    for name, config in profiles.items():
        if not isinstance(config, dict):
            continue
        network = config.get("network", {})
        if isinstance(network, dict) and network.get("enabled") is True:
            add("codex.permissions.network_enabled", "high" if name == selected else "medium",
                "Codex custom permission profile enables network access")
        if name == selected:
            parent_name = config.get("extends")
            parent = profiles.get(parent_name, {}) if isinstance(parent_name, str) else {}
            if root_write(config.get("filesystem")) or (isinstance(parent, dict) and root_write(parent.get("filesystem"))):
                add("codex.permissions.custom_full_disk", "high", "Codex active custom permissions allow writing a filesystem root")
    windows = data.get("windows", {})
    return [], findings, {
        "default_permissions": sanitize_text(selected),
        "approvals_reviewer": data.get("approvals_reviewer") if data.get("approvals_reviewer") in ("user", "auto_review") else "unset",
        "custom_permission_profiles": len(profiles),
        "windows_sandbox": sanitize_text(str(windows.get("sandbox", "unset"))) if isinstance(windows, dict) else "unset",
        "legacy_approval_policy": policy if policy in ("untrusted", "on-failure") else "unset",
    }


def _calls(text):
    """Token boundaries respect comments, escaped quotes and multiline strings."""
    # Offsets must follow tokenize's line splitting (\n only), not str.splitlines,
    # which also breaks on \x0c,   and friends and would skew the slices.
    offsets = [0]
    for line in io.StringIO(text).readlines():
        offsets.append(offsets[-1] + len(line))
    tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            tokens.append(token)
    except (tokenize.TokenError, IndentationError):
        pass
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.type == tokenize.NAME and token.string in ("prefix_rule", "network_rule"):
            j = i + 1
            if j < len(tokens) and tokens[j].string == "(":
                depth = 0
                for end in range(j, len(tokens)):
                    t = tokens[end]
                    if t.type == tokenize.OP:
                        if t.string == "(":
                            depth += 1
                        elif t.string == ")":
                            depth -= 1
                            if not depth:
                                yield text[offsets[token.start[0]-1] + token.start[1]:offsets[t.end[0]-1] + t.end[1]]
                                i = end
                                break
                else:
                    yield ""
        i += 1


def _basename(token):
    return re.split(r"[\\/]", token)[-1].lower()


def _valid_pattern(pattern):
    """Return pattern if it is a non-empty list of strings / unions of strings."""
    def ok(element):
        if isinstance(element, str):
            return True
        return isinstance(element, list) and bool(element) and all(isinstance(v, str) for v in element)
    if not isinstance(pattern, list) or not pattern or not isinstance(pattern[0], str):
        raise ValueError("bad pattern")
    if not all(ok(p) for p in pattern):
        raise ValueError("bad pattern element")
    return pattern


def collect_permissions(tp, rules, findings, *, repo_roots=None, managed_dirs=None, config_parser=None):
    summary = dict(profile_files=0, profile_names=[], rules_files=0, rules_allow=0,
                   rules_prompt=0, rules_forbidden=0, rules_network=0, rules_unparsed=0,
                   hooks_json_handlers=0, project_layers_trusted=0, project_layers_untrusted=0,
                   managed_requirements_present=False, managed_config_present=False,
                   managed_allowed_approval_policies=[], managed_allowed_sandbox_modes=[],
                   managed_allowed_permission_profiles=[], managed_allowed_approvals_reviewers=[],
                   managed_default_permissions="", desktop_agent_mode="unset",
                   desktop_skip_full_access_confirm=False, desktop_thread_permissions=0,
                   desktop_threads_full_access=0, desktop_threads_approval_never=0,
                   desktop_threads_auto_review=0, desktop_threads_network=0)

    def load(path, label, json=False):
        data, error = (load_jsonc if json else load_toml)(path)
        if error or data is not None and not isinstance(data, dict):
            findings.append(make_finding("codex.config.parse_error", "low", "General Tooling",
                                         f"Codex could not parse {label}", sample_redacted=error or "expected table/object"))
            return {}
        return data or {}

    def config(path, label, user=False):
        data = load(path, label)
        _, new, bits = evaluate_permission_keys(data, layer_label=label)
        if not user and config_parser is not None:
            old_rules, old_findings = config_parser(data)
            is_profile = label.startswith("profile ")
            title_prefix = (f"Codex profile {sanitize_text(label[8:])}: " if is_profile else
                            "Codex project config: " if label.startswith("project") else
                            "Codex managed defaults: ")
            for finding in old_findings:
                if finding["id"] == "codex.approval.never" and any(f["id"] == finding["id"] for f in new):
                    continue
                finding["title"] = title_prefix + finding["title"]
                if is_profile:
                    finding["severity"] = SEVERITY_DOWNGRADE.get(finding["severity"], finding["severity"])
                new.append(finding)
            for rule in old_rules:
                if label.startswith("project"):
                    rule["scope"] = "project"
                    rule["source_kind"] = "project_config"
                rules.append(rule)
        if label.startswith("profile "):
            # Profiles are latent (only active with --profile), so give their findings
            # distinct ids: the access map keys on ids like codex.approval.never and
            # must not treat an unselected profile as the live setting.
            for finding in new:
                fid = finding["id"]
                if fid.startswith("codex.") and not fid.startswith("codex.profile."):
                    finding["id"] = "codex.profile." + fid[len("codex."):].replace(".", "_")
        # The existing parser already emits approval.never for the user layer.
        findings.extend(f for f in new if not (user and f["id"] == "codex.approval.never" and
                        any(old["id"] == f["id"] for old in findings)))
        if user:
            summary.update(bits)
        return data

    user = config(tp.codex_config, "user config.toml", True)
    for path in sorted(tp.codex_home.glob("*.config.toml")):
        name = path.name[:-len(".config.toml")]
        summary["profile_files"] += 1
        summary["profile_names"].append(sanitize_text(name))
        config(path, "profile " + name)

    saved = 0
    def rule_files(folder, project=False):
        nonlocal saved
        for path in sorted((folder / "rules").glob("*.rules")):
            summary["rules_files"] += 1
            try:
                if path.stat().st_size > MAX_CONFIG_BYTES:
                    raise OSError("rules file too large")
                text = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeError):
                summary["rules_unparsed"] += 1
                continue
            broad = []
            for call in _calls(text):
                try:
                    node = ast.parse(call, mode="eval").body
                    if not isinstance(node, ast.Call) or node.args:
                        raise ValueError("unsupported call shape")
                    kwargs = {k.arg: ast.literal_eval(k.value) for k in node.keywords}
                    decision = kwargs.get("decision", "allow")
                    if decision not in DECISION_MAP:
                        raise ValueError("unknown decision")
                    if node.func.id == "network_rule":
                        host = kwargs.get("host")
                        if not isinstance(host, str) or not host:
                            raise ValueError("bad host")
                        if decision != "allow":
                            continue
                        kind, rendered, command = "web_fetch", f"WebFetch({host})", host
                        summary["rules_network"] += 1
                    else:
                        pattern = _valid_pattern(kwargs.get("pattern"))
                        inner = " ".join(p if isinstance(p, str) else "{" + "|".join(p) + "}" for p in pattern)
                        command = _basename(pattern[0])
                        exe = command.removesuffix(".exe")
                        kind = "powershell" if exe in ("powershell", "pwsh") else "bash"
                        shown = inner[:160] + ("…" if len(inner) > 160 else "")
                        rendered = ("PowerShell" if kind == "powershell" else "Bash") + f"({shown} *)"
                        summary["rules_" + decision] += 1
                        # Replace matching session prefixes, preserving the durable file rule.
                        aliases = {sanitize_text(a) for a in (inner, inner + " *", rendered, str(pattern))}
                        rules[:] = [r for r in rules
                                    if not (r.get("source_kind", "").startswith("session") and r["rule"] in aliases)]
                        if decision == "allow":
                            saved += 1
                            bare = len(pattern) == 1
                            exec_flag = (len(pattern) == 2 and isinstance(pattern[1], str)
                                         and pattern[1].lower() in EXEC_FLAGS)
                            if exe in INTERPRETERS and (bare or exec_flag):
                                broad.append(rendered)
                    rules.append(make_rule(
                        "codex", "project" if project else "user", "rules", kind, rendered,
                        DECISION_MAP[decision], command_or_tool=command,
                        source_kind="project_config" if project else "user_config",
                        settings_source="project .codex/rules" if project else "rules/" + sanitize_text(path.name),
                        confidence="high"))
                except (ValueError, SyntaxError, TypeError, AttributeError, RecursionError, MemoryError):
                    summary["rules_unparsed"] += 1
            if broad:
                findings.append(make_finding("codex.rules.interpreter_prefix", "high", "Shell Execution",
                    "Codex saved command rules allow arbitrary interpreter execution", evidence_count=len(broad), sample_redacted="; ".join(broad[:3])))

    def hooks(folder, project=False):
        data = load(folder / "hooks.json", "project hooks.json" if project else "user hooks.json", True)
        events = data.get("hooks", {})
        if not isinstance(events, dict):
            return
        for event, groups in events.items():
            handlers = []
            if isinstance(groups, list):
                for group in groups:
                    if isinstance(group, dict):
                        children = group.get("hooks", [group])
                        if isinstance(children, list):
                            handlers.extend(h for h in children if isinstance(h, dict) and h.get("type") == "command" and isinstance(h.get("command"), str))
            summary["hooks_json_handlers"] += len(handlers)
            if handlers:
                severity = "high" if event in ("PreToolUse", "PermissionRequest") else "medium"
                source = "project hooks.json" if project else "hooks.json"
                findings.append(make_finding(
                    "codex.hooks.lifecycle_command", severity, "Shell Execution",
                    f"Codex hook {sanitize_text(str(event))} configured with command ({source})",
                    evidence_count=len(handlers), sample_redacted=clip_sanitized(handlers[0]["command"], 80)))

    rule_files(tp.codex_home)
    hooks(tp.codex_home)
    def normalized(path):
        return os.path.normcase(os.path.normpath(str(path))).replace("\\", "/").casefold()
    projects = user.get("projects", {})
    trusted = {normalized(p) for p, value in projects.items() if isinstance(value, dict) and value.get("trust_level") == "trusted"} if isinstance(projects, dict) else set()
    visited = set()
    for root in default_repo_roots() if repo_roots is None else repo_roots:
        root = Path(root)
        try:
            candidates = [root] + sorted(p for p in root.iterdir() if p.is_dir())
        except OSError:
            candidates = [root]
        for candidate in candidates:
            key = normalized(candidate)
            if key in visited or not (candidate / ".codex").is_dir():
                continue
            visited.add(key)
            if key not in trusted:
                summary["project_layers_untrusted"] += 1
                continue
            summary["project_layers_trusted"] += 1
            folder = candidate / ".codex"
            config(folder / "config.toml", "project .codex/config.toml")
            rule_files(folder, True)
            hooks(folder, True)
    if saved:
        findings.append(make_finding("codex.rules.saved_allow", "low", "Shell Execution", f"Codex has {saved} saved always-allow command rules", evidence_count=saved, tags=["durable_allowlist"]))

    if managed_dirs is None:
        managed_dirs = [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OpenAI" / "Codex"] if os.name == "nt" else [Path("/etc/codex")]
    for folder in managed_dirs:
        folder = Path(folder)
        requirements = folder / "requirements.toml"
        if requirements.is_file():
            summary["managed_requirements_present"] = True
            data = load(requirements, "requirements.toml")
            for key in ("allowed_approval_policies", "allowed_sandbox_modes", "allowed_approvals_reviewers"):
                values = data.get(key, [])
                if isinstance(values, list):
                    summary["managed_" + key] = [sanitize_text(v) for v in values if isinstance(v, str)]
            allowed = data.get("allowed_permission_profiles", {})
            if isinstance(allowed, dict):
                summary["managed_allowed_permission_profiles"] = [sanitize_text(k) for k, v in allowed.items() if v is True]
            summary["managed_default_permissions"] = sanitize_text(str(data.get("default_permissions", "")))
            notes = []
            if "allowed_approval_policies" in data and "never" not in summary["managed_allowed_approval_policies"]:
                notes.append("approval never not allowed")
            if "allowed_permission_profiles" in data and ":danger-full-access" not in summary["managed_allowed_permission_profiles"]:
                notes.append("full access profile not allowed")
            if "allowed_sandbox_modes" in data and "danger-full-access" not in summary["managed_allowed_sandbox_modes"]:
                notes.append("danger-full-access sandbox not allowed")
            findings.append(make_finding("codex.managed.requirements_present", "low", "General Tooling", "Codex admin requirements.toml constrains settings", sample_redacted="; ".join(notes)))
        if (folder / "managed_config.toml").is_file():
            summary["managed_config_present"] = True
            config(folder / "managed_config.toml", "managed_config.toml")

    state = load(tp.codex_home / ".codex-global-state.json", ".codex-global-state.json", True)
    atoms = state.get("electron-persisted-atom-state", {})
    if isinstance(atoms, dict):
        modes = atoms.get("agent-mode-by-host-id", {})
        mode = modes.get("local", next(iter(modes.values()), "unset")) if isinstance(modes, dict) else "unset"
        selection = atoms.get("permission-selection-by-host-id:local", {})
        if mode == "unset" and isinstance(selection, dict) and selection.get("kind") == "agent-mode":
            mode = selection.get("agentMode", "unset")
        # Only the selected permission-mode value is read into evidence.
        normalized_mode = re.sub(r"[-_]", "", str(mode)).lower()
        full = normalized_mode in ("fullaccess", "dangerfullaccess")
        if full:
            summary["desktop_agent_mode"] = "full-access"
        elif isinstance(mode, str):
            summary["desktop_agent_mode"] = sanitize_text(mode[:64])
        else:
            summary["desktop_agent_mode"] = "unset"
        summary["desktop_skip_full_access_confirm"] = atoms.get("skip-full-access-confirm") is True
        threads = atoms.get("heartbeat-thread-permissions-by-id", {})
        if isinstance(threads, dict):
            for thread in threads.values():
                if not isinstance(thread, dict):
                    continue
                summary["desktop_thread_permissions"] += 1
                sandbox = thread.get("sandboxPolicy", {})
                sandbox = sandbox if isinstance(sandbox, dict) else {}
                conditions = (
                    ("full_access", sandbox.get("type") == "dangerFullAccess"),
                    ("approval_never", thread.get("approvalPolicy") == "never"),
                    ("auto_review", thread.get("approvalsReviewer") == "auto_review"),
                    ("network", sandbox.get("networkAccess") is True),
                )
                for key, condition in conditions:
                    summary["desktop_threads_" + key] += int(condition)
        if full:
            sample = "agent-mode=full-access"
            if summary["desktop_skip_full_access_confirm"]:
                sample += "; full-access confirmation skipped"
            findings.append(make_finding(
                "codex.desktop.full_access_mode", "critical", "Shell Execution",
                "Codex Desktop agent mode is Full access (no sandbox, no approvals)", sample_redacted=sample))
        n, m = summary["desktop_threads_full_access"], summary["desktop_threads_approval_never"]
        if n or m:
            findings.append(make_finding(
                "codex.desktop.thread_full_access", "high", "Shell Execution",
                "Codex Desktop threads have full access or bypass approvals",
                evidence_count=max(n, m), sample_redacted=f"{n} threads dangerFullAccess, {m} approval never"))
    auto = [f for f in findings if f["id"] == "codex.approval.auto_review"]
    count = summary["desktop_threads_auto_review"]
    # Latent profile findings retain their downgraded severity and stay separate.
    active = [f for f in auto if f["severity"] == "medium"]
    if active:
        extra = active[1:]
        active[0]["evidence_count"] += count + sum(f["evidence_count"] for f in extra)
        findings[:] = [f for f in findings if not any(f is e for e in extra)]
    elif count:
        # No config key anywhere: only Desktop thread records use auto_review, so
        # do not claim the global setting is auto_review.
        noun = "thread uses" if count == 1 else "threads use"
        findings.append(make_finding(
            "codex.desktop.thread_auto_review", "medium", "General Tooling",
            f"{count} Codex Desktop {noun} auto_review approvals",
            evidence_count=count, sample_redacted=f"{count} Desktop threads with approvalsReviewer=auto_review"))
    effective = summary["default_permissions"]
    if summary["desktop_agent_mode"] == "full-access":
        effective = "full-access (desktop app)"
    elif effective == "unset":
        sandbox_mode = user.get("sandbox_mode", "unset")
        effective = sanitize_text(sandbox_mode) if isinstance(sandbox_mode, str) else "unset"
    summary["effective_permissions"] = effective
    return summary
