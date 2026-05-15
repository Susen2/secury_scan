import re
from .base import BaseSkill, SkillFinding


class AuthSecuritySkill(BaseSkill):
    name = "auth_security"
    description = "Detect authentication weaknesses, crypto issues, and authorization bypass patterns"

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if re.search(r'(?i)hashlib\.(md5|sha1)\s*\(', stripped):
                findings.append(SkillFinding(
                    severity="high",
                    category="weak_hash",
                    title="Weak Hash Algorithm (MD5/SHA1)",
                    description="MD5 or SHA1 used for hashing. These are cryptographically broken and should not be used for security purposes (passwords, signatures).",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use SHA-256 or stronger: hashlib.sha256(). For passwords, use passlib with bcrypt/argon2.",
                ))

            if re.search(r'(?i)random\.(random|choice|randint|randrange|sample)\s*\(', stripped):
                findings.append(SkillFinding(
                    severity="medium",
                    category="insecure_random",
                    title="Insecure Random Number Generator",
                    description="random module used for security-sensitive operations. This is not cryptographically secure and can be predicted.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use secrets module for security-sensitive randomness: secrets.token_hex(), secrets.choice().",
                ))

            if re.search(r'(?i)(if\s+not\s+user|user\s+is\s+None|\.first\(\))\s*(?:\n|:).*?(?:verify_password|check.*?password|authenticate)', stripped, re.DOTALL):
                if i < len(lines) - 5:
                    context = "\n".join(l.strip() for l in lines[i-1:i+5])
                    if re.search(r'verify_password', context) and not re.search(r'verify_password.*pwd_ctx\.verify', context):
                        findings.append(SkillFinding(
                            severity="low",
                            category="login_timing_enum",
                            title="Potential Username Enumeration via Timing",
                            description="Login may return early for non-existent users before calling verify_password, creating a timing difference that enables username enumeration.",
                            line=i,
                            evidence=stripped[:150],
                            remediation="Always run password verification (or a dummy hash check) even when the user doesn't exist, to maintain constant-time behavior.",
                        ))

            if re.search(r'(?i)JWT_ALGORITHM\s*=\s*["\']none["\']', stripped):
                findings.append(SkillFinding(
                    severity="critical",
                    category="jwt_none_algorithm",
                    title="JWT Algorithm Set to None",
                    description="JWT_ALGORITHM = 'none' allows unsigned tokens — anyone can forge valid tokens.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use HMAC-SHA256 (HS256) at minimum, or RS256 with proper key management.",
                ))

            if re.search(r'(?i)JWT_EXPIRE_MINUTES\s*=\s*\d{4,}', stripped):
                findings.append(SkillFinding(
                    severity="low",
                    category="jwt_long_expiry",
                    title="JWT Token with Very Long Expiry",
                    description="JWT token expiry is unusually long (over 1000 minutes). Long-lived tokens increase risk if leaked.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Use shorter token lifetimes (e.g., 15-60 minutes) with refresh token rotation.",
                ))

            if re.search(r'(?i)(with_for_update|SELECT.*FOR UPDATE)', stripped):
                findings.append(SkillFinding(
                    severity="info",
                    category="row_level_lock",
                    title="Database Row Lock Used",
                    description="FOR UPDATE row-level locking detected — this is good for preventing race conditions in concurrent operations.",
                    line=i,
                    evidence=stripped[:150],
                    remediation="Ensure this lock is used correctly with proper transaction isolation levels.",
                ))

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            m = re.search(r'(?i)(CryptContext|bcrypt)(?!.*deprecated\s*=\s*["\']auto["\'])', stripped)
            if m:
                has_auto = any(re.search(r'deprecated\s*=\s*["\']auto["\']', lines[j].strip()) for j in range(max(0, i-2), min(len(lines), i+3)))
                if not has_auto:
                    findings.append(SkillFinding(
                        severity="low",
                        category="crypto_deprecated",
                        title="CryptContext Without deprecated='auto'",
                        description="CryptContext used without deprecated='auto' — old hash schemes won't be automatically upgraded.",
                        line=i,
                        evidence=stripped[:150],
                        remediation="Set deprecated='auto' in CryptContext to automatically upgrade old hashes: CryptContext(schemes=['bcrypt'], deprecated='auto')",
                    ))

        return findings
