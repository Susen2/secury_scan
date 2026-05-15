from dataclasses import dataclass, field


@dataclass
class SkillFinding:
    severity: str
    category: str
    title: str
    description: str
    line: int = 0
    file_path: str = ""
    remediation: str = ""
    evidence: str = ""
    source: str = "local_rule"


class BaseSkill:
    name: str = "base"
    description: str = ""

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        return []

    def analyze_files(self, files: list[tuple[str, str]]) -> list[SkillFinding]:
        all_findings: list[SkillFinding] = []
        for path, content in files:
            findings = self.analyze_file(path, content)
            for f in findings:
                if not f.file_path:
                    f.file_path = path
            all_findings.extend(findings)
        return all_findings
