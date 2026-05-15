import re
from .base import BaseSkill, SkillFinding

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*["\']([\w\-+/=]{20,})["\']', "critical", "API Key", "Hardcoded API key or access token"),
    (r'(?i)(jwt[_-]?secret|secret[_-]?key|signing[_-]?key)\s*[:=]\s*["\']([\w\-+/=]{8,})["\']', "critical", "JWT/Crypto Secret", "Hardcoded JWT secret or signing key"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\'\s]{3,})["\']', "high", "Password", "Hardcoded password"),
    (r'(?i)(sk-[\w\-]{20,})', "critical", "Secret Key", "Hardcoded secret key (sk- prefix)"),
    (r'(?i)(ark-[\w\-]{20,})', "critical", "ARK Key", "Hardcoded ARK API key"),
    (r'(?i)os\.getenv\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']{6,})["\']\s*\)', "medium", "Default Secret", "os.getenv with hardcoded default value as fallback secret"),
    (r'(?i)\bsecret\b\s*=\s*["\'][^"\']+["\']', "high", "Secret Variable", "Variable named 'secret' with hardcoded value"),
]


class SecretsDetectionSkill(BaseSkill):
    name = "secrets_detection"
    description = "Detect hardcoded credentials, API keys, passwords, and tokens in source code"

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            for pattern, severity, category, title in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    evidence = line.strip()
                    findings.append(SkillFinding(
                        severity=severity,
                        category=f"hardcoded_credentials_{category.lower().replace(' ', '_')}",
                        title=f"Hardcoded {title}: {match.group(2) if len(match.groups()) >= 2 else match.group(1)[:20]}...",
                        description=f"Hardcoded credential found at line {i}. This secret is exposed in source code and could be leaked via version control.",
                        line=i,
                        evidence=evidence[:120],
                        remediation="Move this value to an environment variable (os.getenv) or a secure secrets manager. Add the config file to .gitignore and rotate the exposed key immediately.",
                    ))
                    break

        return findings
