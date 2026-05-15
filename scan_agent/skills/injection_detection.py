import re
from .base import BaseSkill, SkillFinding

DANGEROUS_PATTERNS = [
    (r'\beval\s*\(', "high", "eval() call", "eval() executes arbitrary Python code from a string. If the input comes from user data, it allows remote code execution.", "Replace eval() with safer alternatives like ast.literal_eval(), json.loads(), or a custom parser."),
    (r'\bexec\s*\(', "critical", "exec() call", "exec() executes arbitrary Python code. It should never be used with untrusted input.", "Avoid exec() entirely. If dynamic execution is required, use a restricted sandbox."),
    (r'\bcompile\s*\(\s*[^,]+,\s*[^,]+,\s*[\'"]exec[\'"]', "high", "compile() with 'exec' mode", "compile() in 'exec' mode can execute arbitrary code from a string.", "Use compile() only with 'eval' mode on trusted expressions, or avoid dynamic compilation."),
    (r'\b__import__\s*\(', "medium", "__import__() call", "__import__() can dynamically import modules. If user-controlled, it could load malicious modules.", "Use importlib.import_module() with a whitelist of allowed module names."),
    (r'\bgetattr\s*\(\s*\w+\s*,\s*[^)]*user|request|input|param', "medium", "Dynamic attribute access", "getattr() with potentially user-controlled attribute name could access sensitive attributes.", "Use a whitelist of allowed attribute names, or avoid dynamic attribute access."),
]

INJECTION_PATTERNS = [
    (r'(?i)(execute|cursor\.execute)\s*\(.*?(?:f["\']|"|\')\s*(?:SELECT|INSERT|UPDATE|DELETE)', "critical", "SQL Injection", "String formatting in SQL query. Use parameterized queries instead.", "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"),
    (r'(?i)(execute|cursor\.execute)\s*\(.*?%s|\.format\(', "high", "SQL Injection", "String formatting in SQL execution may lead to SQL injection if user input is interpolated.", "Use parameterized queries with placeholders: cursor.execute('SELECT ...', params)"),
    (r'\bsubprocess\.\w+\s*\(.*?shell\s*=\s*True', "critical", "Command Injection", "subprocess with shell=True allows shell injection if any part of the command contains user input.", "Use shell=False with a list of arguments: subprocess.run(['cmd', 'arg1'], shell=False)"),
    (r'\bos\.system\s*\(', "high", "Command Injection", "os.system() passes the command string to a shell, enabling command injection.", "Use subprocess.run() with shell=False and a list of arguments."),
    (r'\bos\.popen\s*\(', "medium", "Command Injection", "os.popen() opens a pipe to a shell command and can be vulnerable to injection.", "Use subprocess.run() or subprocess.Popen() with shell=False."),
    (r'requests\.(get|post|put|delete|patch)\s*\(.*?\{', "high", "SSRF", "Dynamic URL construction with requests library — if any variable is user-controlled, this enables SSRF.", "Validate and whitelist URLs before making requests. Use urlparse and check the hostname."),
    (r'urllib\.request\.urlopen\s*\(.*?\{', "high", "SSRF", "Dynamic URL construction with urllib — user-controlled URLs enable SSRF.", "Validate and whitelist URLs before opening. Block internal IP ranges."),
]

DESERIALIZATION_PATTERNS = [
    (r'pickle\.(load|loads)\s*\(', "critical", "Insecure Deserialization", "pickle.load()/loads() on untrusted data allows arbitrary code execution.", "Never unpickle untrusted data. Use json, msgpack, or a safe serialization format."),
    (r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)', "high", "Insecure Deserialization", "yaml.load() without SafeLoader can instantiate arbitrary Python objects.", "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)."),
    (r'marshal\.loads?\s*\(', "high", "Insecure Deserialization", "marshal.load()/loads() on untrusted data can execute code.", "Avoid marshal for untrusted data. Use a safe serialization format."),
]

ALL_PATTERNS = DANGEROUS_PATTERNS + INJECTION_PATTERNS + DESERIALIZATION_PATTERNS


class InjectionDetectionSkill(BaseSkill):
    name = "injection_detection"
    description = "Detect dangerous functions, injection risks, insecure deserialization, and SSRF patterns"

    def analyze_file(self, file_path: str, content: str) -> list[SkillFinding]:
        findings: list[SkillFinding] = []
        lines = content.split("\n")

        for i, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith("#"):
                continue

            for pattern, severity, title, description, remediation in ALL_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append(SkillFinding(
                        severity=severity,
                        category=title.lower().replace(" ", "_").replace("(", "").replace(")", "").replace(".", "_"),
                        title=title,
                        description=description,
                        line=i,
                        evidence=line_stripped[:150],
                        remediation=remediation,
                    ))
                    break

        return findings
