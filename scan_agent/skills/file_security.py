import re
from .base import BaseSkill, SkillFinding


class FileSecuritySkill(BaseSkill):
    name = "file_security"
    description = "Detect path traversal, insecure file operations, file permission issues, and unsafe file handling"

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if re.search(r'\bos\.chmod\s*\(.*?0o777', stripped):
                findings.append(SkillFinding(
                    severity="high",
                    category="insecure_file_permissions",
                    title="World-Writable File Permissions (0o777)",
                    description="os.chmod with 0o777 makes a file readable, writable, and executable by everyone on the system.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use restrictive permissions: 0o600 for private files, 0o644 for public read-only files.",
                ))

            if re.search(r'\bopen\s*\(\s*.*?["\']w["\']', stripped) and not re.search(r'with\s+open', stripped):
                findings.append(SkillFinding(
                    severity="low",
                    category="file_not_closed",
                    title="File Opened Without Context Manager",
                    description="File opened with open() without using 'with' statement — file may not be properly closed on errors.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use 'with open() as f:' context manager to guarantee file closure.",
                ))

            if re.search(r'(?i)\.\.\/|\.\.\\', stripped):
                found_traversal = False
                for j in range(max(0, i-3), min(len(lines), i+3)):
                    if re.search(r'os\.path\.(realpath|abspath|normpath|commonpath)', lines[j]):
                        found_traversal = True
                        break
                if not found_traversal:
                    findings.append(SkillFinding(
                        severity="medium",
                        category="path_traversal_risk",
                        title="Path Contains '..' Without Validation",
                        description="Path includes '../' or '..\\' without visible path validation (realpath/abspath). This could enable directory traversal.",
                        line=i,
                        evidence=stripped[:150],
                        remediation="Use os.path.realpath() and verify the result is within the expected directory.",
                    ))

            if re.search(r'\bos\.path\.join\s*\([^)]*UPLOAD_DIR|os\.path\.join\s*\([^)]*FRONTEND_DIR', stripped):
                findings.append(SkillFinding(
                    severity="medium",
                    category="file_path_join",
                    title="Path Join with Variable Directory",
                    description="os.path.join used with user-accessible variable to construct file paths without visible realpath check.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="After joining, call os.path.realpath() and verify the result starts with the allowed base directory.",
                ))

            if re.search(r'\bos\.makedirs?\s*\(.*?exist_ok\s*=\s*True', stripped):
                findings.append(SkillFinding(
                    severity="low",
                    category="directory_creation",
                    title="Directory Created with exist_ok=True",
                    description="os.makedirs with exist_ok=True — ensure the directory path is not user-controlled, or a race condition could allow creating directories elsewhere.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Validate the directory path before creation. Consider setting explicit permissions: os.makedirs(path, mode=0o700, exist_ok=True)",
                ))

            if re.search(r'(?i)(os\.remove|os\.unlink|shutil\.rmtree)\s*\(', stripped):
                findings.append(SkillFinding(
                    severity="medium",
                    category="file_deletion",
                    title="File/Directory Deletion Operation",
                    description="File deletion operation detected — verify the path is not user-controlled to prevent arbitrary file deletion.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Validate and sanitize the file path. Use os.path.realpath() and verify it's within an allowed directory.",
                ))

            if re.search(r'(?i)(aiofiles\.open|async\s+with\s+aiofiles)', stripped):
                context_lines = lines[max(0, i-1):min(len(lines), i+3)]
                context = "\n".join(context_lines)
                if re.search(r'(?i)(read|write)\s*\(', context) and not re.search(r'(?i)(os\.path\.realpath|os\.path\.abspath)', context):
                    findings.append(SkillFinding(
                        severity="low",
                        category="async_file_operation",
                        title="Async File Operation Without Path Validation",
                        description="aiofiles.open used for file read/write without visible path sanitization in nearby lines.",
                        line=i,
                        evidence=stripped[:150],
                        remediation="Validate and sanitize the file path before async file operations.",
                    ))

        return findings
