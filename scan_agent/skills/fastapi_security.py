import re
from .base import BaseSkill, SkillFinding


FASTAPI_PATTERNS = [
    (
        r'allow_origins\s*=\s*\[["\']\*["\']\]',
        "high",
        "CORS Wildcard",
        "CORS configured with allow_origins=['*'] allows any website to make cross-origin requests. Combined with allow_credentials=True, this is a security misconfiguration.",
        "Restrict CORS to specific trusted origins: allow_origins=['https://yourdomain.com']",
    ),
    (
        r'(?=.*allow_credentials\s*=\s*True)(?=.*allow_origins\s*=\s*\[["\']\*["\']\])',
        "critical",
        "CORS Wildcard with Credentials",
        "allow_origins=['*'] with allow_credentials=True is not valid per CORS spec and indicates a dangerous misconfiguration.",
        "Set allow_origins to a specific domain list when allow_credentials=True.",
    ),
    (
        r'CORSMiddleware(?!.*allow_origins\s*=\s*\[)',
        "medium",
        "CORS Without Explicit Origins",
        "CORSMiddleware added without explicit allow_origins — check if the default configuration is permissive.",
        "Explicitly set allow_origins to a list of trusted domains.",
    ),
    (
        r'reload\s*=\s*True',
        "medium",
        "Debug Reload in Production",
        "uvicorn/uvloop reload=True enables auto-reload and debug mode. In production this exposes stack traces and allows code reload attacks.",
        "Set reload=False in production. Use an environment variable to control this: reload=os.getenv('DEBUG', 'false').lower() == 'true'",
    ),
    (
        r'debug\s*=\s*True',
        "medium",
        "Debug Mode Enabled",
        "Debug mode enabled in a web framework exposes detailed error pages with stack traces and environment information.",
        "Set debug=False or use an environment variable in production.",
    ),
    (
        r'\bFileResponse\s*\(',
        "medium",
        "FileResponse Used",
        "FileResponse serves files from the server filesystem. Without path validation, this enables path traversal.",
        "Validate that the resolved path is within the allowed directory before calling FileResponse.",
    ),
    (
        r'StaticFiles\s*\([^)]*directory\s*=\s*[^)]*\)',
        "low",
        "StaticFiles Mounted",
        "StaticFiles directory is mounted — verify it doesn't expose sensitive files outside the intended directory.",
        "Ensure the mounted directory only contains public assets and no source code or configuration files.",
    ),
    (
        r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']/(\{[^}]*\}|[^"\']*)\s*["\']\s*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\([^)]*\):',
        "info",
        "FastAPI Route Defined",
        "FastAPI route endpoint — verify this endpoint has proper authentication and authorization checks.",
        "Ensure every sensitive endpoint uses Depends(get_current_user) or equivalent authentication.",
    ),
    (
        r'Depends\s*\(\s*get_db\s*\)',
        "info",
        "Database Session Injection",
        "FastAPI Depends(get_db) provides database access — verify all database queries use parameterized statements.",
        "Review all database queries in this file for SQL injection risks.",
    ),
]

UPLOAD_PATTERNS = [
    (
        r'UploadFile\s*=\s*File\s*\(',
        "medium",
        "File Upload Endpoint",
        "File upload endpoint — verify file type validation is server-side (not just Content-Type header), file size limits are enforced, and uploads are stored outside web root.",
        "Validate files by magic bytes (not Content-Type), enforce size limits, store outside web root, and scan for malware.",
    ),
    (
        r'file\.content_type',
        "high",
        "Content-Type Only Validation",
        "File type validated only by Content-Type header — this is user-controlled and can be spoofed. Attackers can upload malicious files disguised as images.",
        "Validate files by checking magic bytes with a library like python-magic, not by Content-Type header.",
    ),
]


class FastAPISecuritySkill(BaseSkill):
    name = "fastapi_security"
    description = "Audit FastAPI-specific patterns: CORS, route security, file responses, debug mode, and upload validation"

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith("#"):
                continue

            for pattern, severity, title, description, remediation in FASTAPI_PATTERNS + UPLOAD_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                    findings.append(SkillFinding(
                        severity=severity,
                        category=f"fastapi_{title.lower().replace(' ', '_').replace('-', '_')}",
                        title=f"[FastAPI] {title}",
                        description=description,
                        line=i,
                        evidence=line_stripped[:150],
                        remediation=remediation,
                    ))
                    break

        for i, line in enumerate(lines, start=1):
            if re.search(r'os\.path\.join\s*\([^)]*full_path|os\.path\.join\s*\([^)]*path\s*[,\)]', line, re.IGNORECASE) and re.search(r'(full_path|path)', line):
                findings.append(SkillFinding(
                    severity="high",
                    category="fastapi_path_traversal",
                    title="[FastAPI] Path Traversal via os.path.join",
                    description="os.path.join with user-supplied path without validation enables directory traversal attacks.",
                    line=i,
                    evidence=line.strip()[:150],
                    remediation="Use os.path.realpath() and verify the resolved path starts with the allowed base directory.",
                ))

        for i, line in enumerate(lines, start=1):
            if re.search(r'(?i)(str\(e\)|detail\s*=\s*str\(e\))', line):
                findings.append(SkillFinding(
                    severity="medium",
                    category="fastapi_error_disclosure",
                    title="[FastAPI] Error Details Exposed to Client",
                    description="Exception message passed directly to HTTP response. This leaks internal error details (file paths, stack traces) to the client.",
                    line=i,
                    evidence=line.strip()[:150],
                    remediation="Log the full error server-side and return a generic message: raise HTTPException(500, 'Internal server error')",
                ))

        return findings
