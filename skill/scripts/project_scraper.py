#!/usr/bin/env python3
"""Create a compact security review pack for a whole project.

The pack is designed for low-token review: scan many files locally, rank the
highest-signal surfaces, redact likely secrets, and emit bounded snippets.
It produces leads, not final findings.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "dist",
    "build",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "bin",
    "obj",
    "vendor",
    ".idea",
    ".vscode",
}

TEXT_EXTENSIONS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".rs",
    ".cs",
    ".java",
    ".php",
    ".rb",
    ".swift",
    ".kt",
    ".kts",
    ".sql",
    ".prisma",
    ".graphql",
    ".gql",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".env",
    ".example",
    ".md",
    ".sh",
    ".ps1",
    ".dockerfile",
    ".properties",
    ".xml",
    ".gradle",
    ".csproj",
    ".sln",
    ".fs",
    ".fsx",
    ".vb",
    ".scala",
    ".clj",
    ".ex",
    ".exs",
    ".erl",
    ".hrl",
    ".lua",
    ".dart",
}

PROJECT_MARKERS = [
    "package.json",
    "pnpm-workspace.yaml",
    "next.config.js",
    "next.config.mjs",
    "vite.config.ts",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "prisma/schema.prisma",
    "Gemfile",
    "composer.json",
    "mix.exs",
    "pubspec.yaml",
    "Package.swift",
    "deno.json",
    "bun.lockb",
]


@dataclass(frozen=True)
class Rule:
    label: str
    weight: int
    patterns: tuple[str, ...]


RULES = [
    Rule("auth/session", 5, (
        r"\bgetSession\b", r"\bauth\b", r"\bsession\b", r"\bcookie\b", r"\bjwt\b", r"\blogin\b",
        r"\bAuthentication\b", r"\bClaimsPrincipal\b", r"\bUserDetails\b", r"\bSecurityContext\b",
        r"\bDepends\s*\(\s*get_current_user", r"\bcurrent_user\b", r"\brequest\.user\b", r"\bg\.user\b",
    )),
    Rule("authorization", 7, (
        r"\bcan[A-Z]\w*\b", r"\bpermission\b", r"\brole\b", r"\bisAdmin\b", r"\bauthoriz",
        r"\bAuthorize\b", r"\bPreAuthorize\b", r"\bSecured\b", r"\bhasRole\b", r"\bhasAuthority\b",
        r"\bpermission_classes\b", r"\bIsAuthenticated\b", r"\bPolicy\b", r"\bGate::\b",
        r"\bbefore_action\b.*authenticate", r"\bCanCan\b", r"\bPundit\b",
    )),
    Rule("tenant/owner scope", 8, (
        r"\btenantId\b", r"\btenant_id\b", r"\bTenantId\b", r"\bownerId\b", r"\bowner_id\b", r"\bOwnerId\b",
        r"\borganizationId\b", r"\borganization_id\b", r"\bOrganizationId\b", r"\bworkspaceId\b",
        r"\bworkspace_id\b", r"\baccountId\b", r"\baccount_id\b", r"\bcompany_id\b",
    )),
    Rule("privileged mutation", 6, (
        r"\bdelete\b", r"\bremove\b", r"\bdestroy\b", r"\bupdate\b", r"\bpatch\b", r"\bpublish\b",
        r"\bapprove\b", r"\barchive\b", r"\brestore\b", r"\btransfer\b", r"\bsave\b", r"\bSaveChanges\b",
        r"\bDELETE\b", r"\bUPDATE\b", r"\bINSERT\b", r"\bCreate\b", r"\bDestroy\b",
    )),
    Rule("mass assignment", 10, (
        r"\.\.\.\s*(?:body|payload|input|req\.body|data)",
        r"\b(?:req\.body|request\.data|request\.json|params|payload|input)\b",
        r"Object\.assign\s*\(",
        r"Object\.fromEntries\s*\(",
        r"\bBeanUtils\.copyProperties\b",
        r"\bUpdateModelAsync\b",
        r"\bTryUpdateModelAsync\b",
        r"\bMassAssignment\b",
        r"\bfillable\b",
        r"\bguarded\b",
        r"\bpermit\s*\(",
        r"\baccepts_nested_attributes_for\b",
        r"pick\w*\s*\(",
        r"['\"](?:role|tenantId|tenant_id|ownerId|owner_id|organizationId|organization_id|workspaceId|workspace_id|status|visibility|approvedAt|approved_at|deletedAt|deleted_at|reviewerId|reviewer_id|plan|price|quota|isAdmin|is_admin|metadata)['\"]",
    )),
    Rule("storage/signed url", 9, (
        r"\bS3\b", r"\bbucket\b", r"\bstorageBucket\b", r"\bstorage\.", r"\bsignedUrl\b",
        r"\bsigned[-_ ]?url\b", r"\bpresign\w*", r"\bcreateSigned\w*", r"\bgetSigned\w*",
        r"\bobjectKey\b", r"\bfileKey\b", r"\bupload\b", r"\bdownload\b", r"\bBlob\b",
        r"\bMultipartFile\b", r"\bIFormFile\b", r"\bActiveStorage\b", r"\bStorage::disk\b",
    )),
    Rule("public/browser boundary", 5, (
        r"\bpublic\b", r"\bpreview\b", r"\bhelper\b", r"\basset\b", r"\bsafe\b", r"\btemplate\b",
        r"\bdemo\b", r"\btest\b", r"\binternal\b", r"\bsync\b", r"\bdownload\b", r"\bcors\b",
        r"\bcsrf\b", r"\borigin\b", r"\bredirect\b", r"\bcallbackUrl\b", r"\bwebhook\b", r"\bAllowAnyOrigin\b", r"\bCrossOrigin\b",
        r"\bcsrf_exempt\b", r"\bprotect_from_forgery\b", r"\bVerifyCsrfToken\b",
    )),
    Rule("public write/abuse", 6, (r"\blead\b", r"\bcontact\b", r"\bquote\b", r"\bwaitlist\b", r"\brateLimit\b", r"\bthrottle\b", r"\bcaptcha\b")),
    Rule("external side effect", 5, (
        r"\bfetch\s*\(", r"\baxios\b", r"\bsendEmail\b", r"\bsendMail\b", r"\bnotify\b",
        r"\benqueue\b", r"\bqueue\b", r"\brevalidate\b", r"\binvalidate\b", r"\bHttpClient\b",
        r"\bRestTemplate\b", r"\bWebClient\b", r"\brequests\.", r"\bhttp\.Client\b", r"\bFaraday\b",
        r"\bGuzzleHttp\b", r"\bSidekiq\b", r"\bCelery\b", r"\bHangfire\b",
    )),
    Rule("ai/document processing", 6, (r"\bopenai\b", r"\banthropic\b", r"\bprompt\b", r"\bpdf\b", r"\bchromium\b", r"\bpuppeteer\b", r"\bplaywright\b", r"\bocr\b", r"\brender\b", r"\bparse\b")),
    Rule("malformed input", 6, (
        r"\bJSON\.parse\s*\(",
        r"\brequest\.json\s*\(",
        r"\breq\.body\b",
        r"\bbodyParser\b",
        r"\bmultipart\b",
        r"\bFormData\b",
        r"\bparse\b",
        r"\brender\b",
        r"\bitems\.map\s*\(",
        r"\.map\s*\(",
        r"\.toUpperCase\s*\(",
        r"\.toLowerCase\s*\(",
        r"\bcontent-type\b",
        r"\bContent-Type\b",
        r"\bmaxBytes\b",
        r"\bmaxSize\b",
        r"\bfileSize\b",
        r"\bzod\b",
        r"\byup\b",
        r"\bvalidate\b",
    )),
    Rule("money/quota", 8, (r"\bstripe\b", r"\bpayment\b", r"\bprice\b", r"\bamount\b", r"\bcurrency\b", r"\btax\b", r"\bsubscription\b", r"\bcredit\b", r"\bbalance\b", r"\bquota\b", r"\bInvoice\b", r"\bCharge\b")),
    Rule("fail-open/config", 7, (
        r"\bprocess\.env\b", r"\bos\.environ\b", r"\bEnvironment\.GetEnvironmentVariable\b",
        r"\bSystem\.getenv\b", r"\bos\.Getenv\b", r"\bENV\[", r"\benv\(", r"\bfallback\b",
        r"\bdefault\b", r"\benabled\b", r"\bdisable", r"\bfailOpen\b", r"\bmock\b", r"\bdemo\b",
        r"\breturn\s+true\b", r"\bsuccess\s*:\s*true\b", r"\bok\s*:\s*true\b", r"\ballow\b",
        r"\bredis\b", r"\bcache\b", r"\brate[-_ ]?limit\b", r"\bprovider\b",
    )),
    Rule("errors/logs", 4, (
        r"\berror\.message\b", r"\bconsole\.error\b", r"\bconsole\.log\b", r"\blogger\.",
        r"\bstack\b", r"\btrace\b", r"\baudit\b", r"\bprintStackTrace\b", r"\bILogger\b",
        r"\blog\.", r"\bRails\.logger\b", r"\bLog::",
    )),
]

COMPILED_RULES = [
    (rule, tuple(re.compile(pattern, re.IGNORECASE) for pattern in rule.patterns))
    for rule in RULES
]

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(database_url|postgres_url|mysql_url|redis_url|mongodb_uri)\b\s*[:=]\s*['\"]?[^'\"\s]+:[^'\"\s@]+@"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token|password|client[_-]?secret)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(stripe|sendgrid|twilio|slack|github|aws|azure|gcp)[_-]?(secret|token|key)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
]

ROUTE_PATTERNS = [
    re.compile(r"(^|/|\\)app(/|\\).*(/|\\)route\.(ts|js)$"),
    re.compile(r"(^|/|\\)pages(/|\\)api(/|\\).*\.(ts|js)$"),
    re.compile(r"(^|/|\\)api(/|\\).*\.(ts|js|py|go|cs|rb|php|java|kt|rs)$"),
    re.compile(r"(^|/|\\)(routes|controllers|handlers|server-actions|actions|views|endpoints)(/|\\).*\.(ts|tsx|js|jsx|py|go|cs|rb|php|java|kt|rs|ex)$"),
    re.compile(r".*(Controller|Resource|Endpoint|Handler|Router|ViewSet|Servlet|Function)\.(java|kt|cs|py|go|rb|php|rs|ex)$"),
    re.compile(r"(^|/|\\)(urls|views|serializers|permissions|dependencies)\.py$"),
    re.compile(r"(^|/|\\)(routes|api)\.rb$"),
    re.compile(r"(^|/|\\)routes(/|\\).*\.(php|rb|py|js|ts)$"),
    re.compile(r"(^|/|\\)(Program|Startup)\.cs$"),
    re.compile(r"(^|/|\\)main\.go$"),
]

ROUTE_LITERAL_PATTERNS = [
    re.compile(r"['\"](?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+/[^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"\b(?:app|router|route|server)\.(?:get|post|put|patch|delete|options|head)\s*\(\s*['\"]/[^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"\b(?:HandleFunc|Handle|MapGet|MapPost|MapPut|MapPatch|MapDelete|http.HandleFunc)\s*\(\s*['\"]/[^'\"]+['\"]", re.IGNORECASE),
    re.compile(r"@(?:Get|Post|Put|Patch|Delete|RequestMapping|GetMapping|PostMapping|Route)\s*\([^)]*['\"]/[^'\"]+['\"]", re.IGNORECASE),
]

CONFIG_PATTERNS = [
    re.compile(r"(^|/|\\)(\.env.*|.*config\.(ts|js|mjs|json|yaml|yml|py)|docker-compose\.ya?ml|Dockerfile|vercel\.json|appsettings.*\.json|application.*\.(properties|ya?ml))$", re.IGNORECASE),
    re.compile(r"(^|/|\\)(middleware|auth|session|permissions|policy|security|rate-limit|cors|csrf)[^/\\]*\.(ts|js|py|go|cs|java|kt|rb|php|rs)$", re.IGNORECASE),
]


@dataclass
class Snippet:
    line: int
    label: str
    text: str


@dataclass
class FileSummary:
    path: str
    score: int = 0
    labels: dict[str, int] = field(default_factory=dict)
    snippets: list[Snippet] = field(default_factory=list)
    route: bool = False
    config: bool = False
    possible_secret: bool = False


def is_text_candidate(path: Path) -> bool:
    if path.name.startswith(".env"):
        return True
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    if path.name in {"Dockerfile", "Procfile", "Makefile"}:
        return True
    return False


def iter_files(root: Path, max_files: int) -> Iterable[Path]:
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if not is_text_candidate(path):
                continue
            seen += 1
            if seen > max_files:
                return
            yield path


def read_text(path: Path, max_bytes: int) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data[:max_bytes].decode("utf-8", errors="replace")


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def redact(line: str) -> str:
    line = line.strip()
    line = re.sub(r"(?i)(password|secret|token|api[_-]?key|client[_-]?secret)(\s*[:=]\s*)['\"]?[^'\"\s,}]+", r"\1\2<redacted>", line)
    line = re.sub(r"(?i)((?:database_url|postgres_url|mysql_url|redis_url|mongodb_uri)\s*[:=]\s*)['\"]?[^'\"\s]+", r"\1<redacted-url>", line)
    line = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "-----BEGIN <redacted> PRIVATE KEY-----", line)
    if len(line) > 170:
        return line[:167] + "..."
    return line


def route_kind(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if any(pattern.search(normalized) for pattern in ROUTE_PATTERNS):
        if "/admin/" in normalized or "/internal/" in normalized:
            return "admin/internal candidate"
        if "/webhook" in normalized or "webhook" in normalized:
            return "webhook candidate"
        if "/public" in normalized or "public" in normalized:
            return "public candidate"
        return "route/action candidate"
    return None


def content_route_kind(text: str) -> str | None:
    if any(pattern.search(text) for pattern in ROUTE_LITERAL_PATTERNS):
        lower = text.lower()
        if "/admin" in lower or "/internal" in lower:
            return "admin/internal route literals"
        if "webhook" in lower:
            return "webhook route literals"
        if "/public" in lower or "public" in lower:
            return "public route literals"
        return "route/action literals"
    return None


def is_config(path: str) -> bool:
    return any(pattern.search(path) for pattern in CONFIG_PATTERNS)


def project_markers(root: Path) -> list[str]:
    markers: list[str] = []
    for marker in PROJECT_MARKERS:
        if (root / marker).exists():
            markers.append(marker)
    for pattern in ("*.csproj", "*.sln"):
        if list(root.glob(pattern)):
            markers.append(pattern)
    return markers


def scan(root: Path, max_files: int, max_bytes: int, snippets_per_file: int) -> dict:
    root = root.resolve()
    summaries: dict[str, FileSummary] = {}
    scanned_files = 0
    scanned_bytes = 0

    for path in iter_files(root, max_files=max_files):
        scanned_files += 1
        relative = rel(path, root)
        text = read_text(path, max_bytes=max_bytes)
        if text is None:
            continue

        scanned_bytes += min(len(text.encode("utf-8", errors="ignore")), max_bytes)
        summary = FileSummary(path=relative)
        kind = route_kind(relative)
        content_kind = content_route_kind(text)
        kind = kind or content_kind
        if kind:
            summary.route = True
            summary.score += 12
            summary.labels[kind] = 1
        if is_config(relative):
            summary.config = True
            summary.score += 8
            summary.labels["config/security helper"] = 1

        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                summary.possible_secret = True
                summary.score += 40
                summary.labels["possible secret"] = summary.labels.get("possible secret", 0) + 1
                add_snippet(summary, line_number, "possible secret", line, snippets_per_file)
                continue

            for rule, patterns in COMPILED_RULES:
                if any(pattern.search(line) for pattern in patterns):
                    summary.score += rule.weight
                    summary.labels[rule.label] = summary.labels.get(rule.label, 0) + 1
                    add_snippet(summary, line_number, rule.label, line, snippets_per_file)

        if summary.score > 0:
            summaries[relative] = summary

    ranked = sorted(summaries.values(), key=lambda item: (-item.score, item.path))
    return {
        "scope": str(root),
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "project_markers": project_markers(root),
        "top_files": [summary_to_dict(item) for item in ranked],
        "routes": [summary_to_dict(item) for item in ranked if item.route],
        "configs": [summary_to_dict(item) for item in ranked if item.config],
        "possible_secrets": [summary_to_dict(item) for item in ranked if item.possible_secret],
        "label_index": build_label_index(ranked),
    }


def add_snippet(summary: FileSummary, line_number: int, label: str, line: str, limit: int) -> None:
    if len(summary.snippets) >= limit:
        return
    snippet = redact(line)
    if not snippet:
        return
    if any(existing.line == line_number and existing.label == label for existing in summary.snippets):
        return
    summary.snippets.append(Snippet(line=line_number, label=label, text=snippet))


def summary_to_dict(summary: FileSummary) -> dict:
    return {
        "path": summary.path,
        "score": summary.score,
        "labels": dict(sorted(summary.labels.items(), key=lambda item: (-item[1], item[0]))),
        "snippets": [asdict(snippet) for snippet in summary.snippets],
        "route": summary.route,
        "config": summary.config,
        "possible_secret": summary.possible_secret,
    }


def build_label_index(ranked: list[FileSummary]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for summary in ranked:
        for label in summary.labels:
            index.setdefault(label, [])
            if len(index[label]) < 12:
                index[label].append(summary.path)
    return dict(sorted(index.items()))


def review_plan(result: dict) -> list[str]:
    plan: list[str] = []
    if result["possible_secrets"]:
        plan.append("Inspect possible secrets/config leaks first.")
    if result["routes"]:
        plan.append("Classify route/action entry points as public, authenticated, role-gated, internal, or webhook-only.")
    labels = result["label_index"]
    for label in [
        "auth/session",
        "authorization",
        "tenant/owner scope",
        "privileged mutation",
        "mass assignment",
        "storage/signed url",
        "public write/abuse",
        "money/quota",
        "ai/document processing",
        "malformed input",
        "fail-open/config",
        "errors/logs",
    ]:
        if label in labels:
            plan.append(f"Follow `{label}` leads and verify guards dominate sinks.")
    return plan[:12]


def append_budget(lines: list[str], line: str, budget: int) -> bool:
    used = sum(len(item) + 1 for item in lines)
    if used + len(line) + 1 > budget:
        return False
    lines.append(line)
    return True


def render_markdown(result: dict, budget_chars: int, top_files: int, top_routes: int) -> str:
    lines: list[str] = []
    for line in [
        "# Secure Pack",
        "",
        f"Scope: `{result['scope']}`",
        f"Files scanned: `{result['scanned_files']}`",
        f"Approx bytes scanned: `{result['scanned_bytes']}`",
    ]:
        append_budget(lines, line, budget_chars)

    if result["project_markers"]:
        append_budget(lines, "Project markers: " + ", ".join(f"`{marker}`" for marker in result["project_markers"]), budget_chars)
    append_budget(lines, "", budget_chars)
    append_budget(lines, "> Static pack only. Read source files before reporting findings.", budget_chars)
    append_budget(lines, "", budget_chars)

    append_budget(lines, "## Review Plan", budget_chars)
    plan = review_plan(result)
    if plan:
        for item in plan:
            append_budget(lines, f"- {item}", budget_chars)
    else:
        append_budget(lines, "- No high-signal leads found by the scraper. Continue with manual framework/config review.", budget_chars)
    append_budget(lines, "", budget_chars)

    append_budget(lines, "## Possible Secrets", budget_chars)
    if result["possible_secrets"]:
        for item in result["possible_secrets"][:10]:
            append_budget(lines, f"- score {item['score']} `{item['path']}`", budget_chars)
            for snippet in item["snippets"][:2]:
                append_budget(lines, f"  - L{snippet['line']} [{snippet['label']}] {snippet['text']}", budget_chars)
    else:
        append_budget(lines, "- None matched built-in patterns.", budget_chars)
    append_budget(lines, "", budget_chars)

    append_budget(lines, "## Route And Action Entry Points", budget_chars)
    if result["routes"]:
        for item in result["routes"][:top_routes]:
            label_list = ", ".join(list(item["labels"])[:4])
            append_budget(lines, f"- score {item['score']} `{item['path']}` ({label_list})", budget_chars)
    else:
        append_budget(lines, "- No common route/action files detected.", budget_chars)
    append_budget(lines, "", budget_chars)

    append_budget(lines, "## Highest-Signal Files", budget_chars)
    for item in result["top_files"][:top_files]:
        label_list = ", ".join(f"{label} x{count}" for label, count in list(item["labels"].items())[:5])
        if not append_budget(lines, f"- score {item['score']} `{item['path']}` ({label_list})", budget_chars):
            break
        for snippet in item["snippets"][:3]:
            if not append_budget(lines, f"  - L{snippet['line']} [{snippet['label']}] {snippet['text']}", budget_chars):
                break
    append_budget(lines, "", budget_chars)

    append_budget(lines, "## Capability Index", budget_chars)
    for label, paths in result["label_index"].items():
        compact_paths = ", ".join(f"`{path}`" for path in paths[:6])
        if len(paths) > 6:
            compact_paths += f", +{len(paths) - 6} more"
        if not append_budget(lines, f"- {label}: {compact_paths}", budget_chars):
            append_budget(lines, "- Output budget reached. Re-run with a larger `--budget-chars` if needed.", budget_chars)
            break

    if sum(len(item) + 1 for item in lines) >= budget_chars - 256:
        lines.append("")
        lines.append("_Truncated by budget._")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a compact whole-project security review pack.")
    parser.add_argument("path", help="Project path to scan")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--budget-chars", type=int, default=18_000, help="Approximate max Markdown output size")
    parser.add_argument("--max-files", type=int, default=12_000)
    parser.add_argument("--max-bytes", type=int, default=600_000, help="Max bytes read per file")
    parser.add_argument("--snippets-per-file", type=int, default=5)
    parser.add_argument("--top-files", type=int, default=35)
    parser.add_argument("--top-routes", type=int, default=80)
    args = parser.parse_args()

    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"Path does not exist: {root}")
    if not root.is_dir():
        root = root.parent

    result = scan(
        root=root,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        snippets_per_file=args.snippets_per_file,
    )
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_markdown(result, budget_chars=args.budget_chars, top_files=args.top_files, top_routes=args.top_routes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
