#!/usr/bin/env python3
"""Build a static security capability inventory for a project.

This script is intentionally conservative: it produces review leads, not
findings. It never executes project code and redacts possible secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
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

CAPABILITY_PATTERNS: dict[str, list[str]] = {
    "auth_session": [
        r"\bauth(?:enticate|orization)?\b",
        r"\bsession\b",
        r"\bcookie\b",
        r"\bjwt\b",
        r"\blogin\b",
        r"\bsignIn\b",
        r"\bmiddleware\b",
        r"\bAuthentication\b",
        r"\bClaimsPrincipal\b",
        r"\bSecurityContext\b",
        r"\bcurrent_user\b",
        r"\brequest\.user\b",
    ],
    "authorization_policy": [
        r"\brole\b",
        r"\bpermission\b",
        r"\bcan[A-Z][A-Za-z0-9_]*\b",
        r"\bisAdmin\b",
        r"\bauthorized?\b",
        r"\bAuthorize\b",
        r"\bPreAuthorize\b",
        r"\bSecured\b",
        r"\bhasRole\b",
        r"\bpermission_classes\b",
        r"\bownerId\b",
        r"\bowner_id\b",
        r"\btenantId\b",
        r"\btenant_id\b",
        r"\borganizationId\b",
        r"\borganization_id\b",
        r"\bworkspaceId\b",
        r"\bworkspace_id\b",
    ],
    "privileged_mutation": [
        r"\bdelete\b",
        r"\bremove\b",
        r"\bdestroy\b",
        r"\bupdate\b",
        r"\bcreate\b",
        r"\bpublish\b",
        r"\bapprove\b",
        r"\barchive\b",
        r"\brestore\b",
        r"\btransfer\b",
        r"\bassign\b",
        r"\bSaveChanges\b",
        r"\bDELETE\b",
        r"\bUPDATE\b",
        r"\bINSERT\b",
    ],
    "policy_field_mass_assignment": [
        r"['\"](?:role|tenantId|ownerId|organizationId|workspaceId|status|visibility|approvedAt|deletedAt|reviewerId|plan|price|quota|isAdmin|metadata)['\"]",
        r"\b(?:role|tenantId|ownerId|organizationId|workspaceId|approvedAt|deletedAt|reviewerId|plan|price|quota|isAdmin|metadata)\s*[?:=]",
        r"\bstatus\s*[:=]\s*['\"](?:draft|review|published|archived|active|inactive|approved|rejected|paid|failed|pending)['\"]",
        r"\bvisibility\s*[:=]\s*['\"](?:private|public|tenant|internal|restricted)['\"]",
    ],
    "storage_upload_signed_url": [
        r"\bS3\b",
        r"\bbucket\b",
        r"\bupload\b",
        r"\bdownload\b",
        r"\bpresign",
        r"\bsignedUrl\b",
        r"\bcreateSigned",
        r"\bgetSigned",
        r"\bpublicUrl\b",
        r"\bobjectKey\b",
        r"\bfileKey\b",
        r"\bMultipartFile\b",
        r"\bIFormFile\b",
        r"\bActiveStorage\b",
        r"\bStorage::disk\b",
    ],
    "public_or_browser_boundary": [
        r"\bpublic\b",
        r"\bpreview\b",
        r"\bhelper\b",
        r"\basset\b",
        r"\bsafe\b",
        r"\btemplate\b",
        r"\bdemo\b",
        r"\btest\b",
        r"\binternal\b",
        r"\bsync\b",
        r"\bdownload\b",
        r"\bCORS\b",
        r"\bcors\b",
        r"\bcsrf\b",
        r"\borigin\b",
        r"\bAccess-Control",
        r"\bwebhook\b",
        r"\bredirect\b",
        r"\bcallbackUrl\b",
        r"\bCrossOrigin\b",
        r"\bcsrf_exempt\b",
        r"\bprotect_from_forgery\b",
    ],
    "public_write_or_abuse": [
        r"\blead\b",
        r"\bcontact\b",
        r"\bquote\b",
        r"\bwaitlist\b",
        r"\brateLimit\b",
        r"\brate-limit\b",
        r"\bthrottle\b",
        r"\bcaptcha\b",
    ],
    "external_side_effects": [
        r"\bfetch\s*\(",
        r"\baxios\b",
        r"\bwebhook\b",
        r"\bsendEmail\b",
        r"\bmail\.send\b",
        r"\btransporter\.sendMail\b",
        r"\bsms\b",
        r"\bnotify\b",
        r"\benqueue\b",
        r"\bqueue\b",
        r"\brevalidate\b",
        r"\binvalidate\b",
        r"\bHttpClient\b",
        r"\bRestTemplate\b",
        r"\brequests\.",
        r"\bSidekiq\b",
        r"\bCelery\b",
    ],
    "ai_document_processing": [
        r"\bopenai\b",
        r"\banthropic\b",
        r"\bLLM\b",
        r"\bprompt\b",
        r"\bpdf\b",
        r"\bchromium\b",
        r"\bpuppeteer\b",
        r"\bplaywright\b",
        r"\bocr\b",
        r"\brender\b",
        r"\bparse\b",
    ],
    "malformed_input": [
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
    ],
    "money_or_quota": [
        r"\bprice\b",
        r"\bamount\b",
        r"\bcurrency\b",
        r"\btax\b",
        r"\bpayment\b",
        r"\bstripe\b",
        r"\bsubscription\b",
        r"\bcredit\b",
        r"\bbalance\b",
        r"\bquota\b",
    ],
    "errors_logs_observability": [
        r"\berror\.message\b",
        r"\bconsole\.error\b",
        r"\bconsole\.log\b",
        r"\blogger\.",
        r"\bstack\b",
        r"\btrace\b",
        r"\baudit\b",
        r"\bprintStackTrace\b",
        r"\bRails\.logger\b",
    ],
    "env_fallback_config": [
        r"\bprocess\.env\b",
        r"\bos\.environ\b",
        r"\bEnvironment\.GetEnvironmentVariable\b",
        r"\bSystem\.getenv\b",
        r"\bos\.Getenv\b",
        r"\bENV\[",
        r"\bfallback\b",
        r"\bdefault\b",
        r"\benabled\b",
        r"\bdisable",
        r"\bfailOpen\b",
        r"\bmock\b",
        r"\bdemo\b",
        r"\breturn\s+true\b",
        r"\bsuccess\s*:\s*true\b",
        r"\bok\s*:\s*true\b",
        r"\ballow\b",
        r"\bredis\b",
        r"\bcache\b",
        r"\brate[-_ ]?limit\b",
        r"\bprovider\b",
    ],
}

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

PROJECT_MARKERS = [
    "package.json",
    "next.config.js",
    "next.config.mjs",
    "vite.config.ts",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "*.csproj",
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
]


@dataclass
class Hit:
    file: str
    line: int
    label: str
    snippet: str


def is_text_candidate(path: Path) -> bool:
    if path.name.startswith(".env"):
        return True
    if path.suffix in TEXT_EXTENSIONS:
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


def redact_snippet(line: str) -> str:
    line = line.strip()
    line = re.sub(r"(?i)(password|secret|token|api[_-]?key|client[_-]?secret)(\s*[:=]\s*)['\"]?[^'\"\s,}]+", r"\1\2<redacted>", line)
    line = re.sub(r"(?i)((?:database_url|postgres_url|mysql_url|redis_url|mongodb_uri)\s*[:=]\s*)['\"]?[^'\"\s]+", r"\1<redacted-url>", line)
    if len(line) > 180:
        return line[:177] + "..."
    return line


def scan(root: Path, max_files: int, max_bytes: int) -> dict:
    root = root.resolve()
    capability_hits: dict[str, list[Hit]] = {key: [] for key in CAPABILITY_PATTERNS}
    secret_hits: list[Hit] = []
    route_files: list[str] = []
    scanned_files = 0
    project_markers: list[str] = []

    for marker in PROJECT_MARKERS:
        if "*" in marker:
            if list(root.glob(marker)):
                project_markers.append(marker)
        elif (root / marker).exists():
            project_markers.append(marker)

    compiled = {
        label: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        for label, patterns in CAPABILITY_PATTERNS.items()
    }

    for path in iter_files(root, max_files=max_files):
        scanned_files += 1
        relative = rel(path, root)
        normalized = relative.replace("\\", "/")
        text = read_text(path, max_bytes=max_bytes)
        if text is None:
            continue
        if any(pattern.search(normalized) for pattern in ROUTE_PATTERNS) or any(pattern.search(text) for pattern in ROUTE_LITERAL_PATTERNS):
            route_files.append(relative)

        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    secret_hits.append(Hit(relative, line_number, "possible_secret", redact_snippet(line)))
                    break

            for label, patterns in compiled.items():
                if len(capability_hits[label]) >= 50:
                    continue
                if any(pattern.search(line) for pattern in patterns):
                    capability_hits[label].append(Hit(relative, line_number, label, redact_snippet(line)))

    ranked_labels = sorted(
        capability_hits,
        key=lambda label: (0 if capability_hits[label] else 1, label),
    )

    return {
        "scope": str(root),
        "scanned_files": scanned_files,
        "project_markers": project_markers,
        "route_files": route_files[:200],
        "capability_hits": {label: [asdict(hit) for hit in capability_hits[label]] for label in ranked_labels if capability_hits[label]},
        "possible_secrets": [asdict(hit) for hit in secret_hits[:100]],
        "suggested_review_order": suggested_order(capability_hits, route_files, secret_hits),
    }


def suggested_order(capability_hits: dict[str, list[Hit]], route_files: list[str], secret_hits: list[Hit]) -> list[str]:
    order: list[str] = []
    if secret_hits:
        order.append("Inspect possible secrets and config leaks first.")
    for label in [
        "auth_session",
        "authorization_policy",
        "privileged_mutation",
        "policy_field_mass_assignment",
        "storage_upload_signed_url",
        "public_or_browser_boundary",
        "public_write_or_abuse",
        "money_or_quota",
        "ai_document_processing",
        "malformed_input",
        "external_side_effects",
        "env_fallback_config",
        "errors_logs_observability",
    ]:
        if capability_hits.get(label):
            order.append(f"Review {label.replace('_', ' ')} surfaces.")
    if route_files:
        order.append("Classify route/action files as public, authenticated, role-gated, internal, or webhook-only.")
    return order[:12]


def render_markdown(result: dict) -> str:
    lines = [
        "# Semantic Security Inventory",
        "",
        f"Scope: `{result['scope']}`",
        f"Files scanned: `{result['scanned_files']}`",
    ]
    if result["project_markers"]:
        lines.append("Project markers: " + ", ".join(f"`{m}`" for m in result["project_markers"]))
    lines.append("")

    lines.append("## Suggested Review Order")
    if result["suggested_review_order"]:
        for item in result["suggested_review_order"]:
            lines.append(f"- {item}")
    else:
        lines.append("- No sensitive leads found by static scan. Continue with manual framework/config review.")
    lines.append("")

    lines.append("## Route And Action Files")
    if result["route_files"]:
        for path in result["route_files"][:80]:
            lines.append(f"- `{path}`")
        if len(result["route_files"]) > 80:
            lines.append(f"- ... {len(result['route_files']) - 80} more")
    else:
        lines.append("- No common route/action files detected.")
    lines.append("")

    lines.append("## Possible Secrets")
    if result["possible_secrets"]:
        for hit in result["possible_secrets"]:
            lines.append(f"- `{hit['file']}:{hit['line']}` {hit['snippet']}")
    else:
        lines.append("- No possible secrets matched the built-in patterns.")
    lines.append("")

    lines.append("## Capability Leads")
    if result["capability_hits"]:
        for label, hits in result["capability_hits"].items():
            lines.append(f"### {label.replace('_', ' ').title()}")
            for hit in hits[:20]:
                lines.append(f"- `{hit['file']}:{hit['line']}` {hit['snippet']}")
            if len(hits) > 20:
                lines.append(f"- ... {len(hits) - 20} more")
            lines.append("")
    else:
        lines.append("- No capability leads matched the built-in patterns.")

    lines.append("> Static inventory only. Treat these as leads, not findings.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a semantic security capability inventory.")
    parser.add_argument("path", help="Project path to scan")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    args = parser.parse_args()

    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"Path does not exist: {root}")
    if not root.is_dir():
        root = root.parent

    result = scan(root, max_files=args.max_files, max_bytes=args.max_bytes)
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
