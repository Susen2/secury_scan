import json
import time
from openai import OpenAI

DEEPSEEK_BASE_URL = "https://api.deepseek.com"

SECURITY_AUDIT_SYSTEM_PROMPT = """You are an expert security auditor specializing in Python code review. Your job is to identify **only real, actionable security vulnerabilities** in the provided Python code.

## What to look for:
1. **Hardcoded credentials**: API keys, passwords, tokens, secrets in source code
2. **Injection risks**: SQL injection, command injection, LDAP injection, XPath injection, template injection (SSTI), header injection
3. **Insecure deserialization**: pickle, yaml.unsafe_load, marshal.loads, eval/exec on untrusted data
4. **Path traversal**: os.path.join with user input, open() with unsanitized paths, zip slip
5. **Cryptographic weaknesses**: MD5/SHA1 for passwords, hardcoded salts, weak random (random module for security), missing crypto nonce verification
6. **Unsafe dynamic execution**: eval(), exec(), compile(), __import__ on untrusted input
7. **SSRF risks**: requests.get/urllib with user-supplied URLs without allowlist validation
8. **Insecure file permissions**: os.chmod with overly permissive modes (0o777)
9. **Subprocess injection**: shell=True with user input, command concatenation
10. **Information disclosure**: verbose error messages, debug mode in production, stack traces exposed
11. **Missing security headers/controls**: CORS misconfiguration (allow_origins=["*"]), missing CSRF
12. **Insecure dependency usage**: Known-vulnerable patterns in PyJWT, lxml, xml.etree (XXE)
13. **Race conditions**: TOCTOU on file operations, unsafe concurrent access patterns
14. **Logging sensitive data**: passwords, tokens, PII in log statements
15. **Request forgery**: Missing origin/referer checks in sensitive endpoints

## Output format:
Return ONLY a valid JSON object with this exact structure:
```json
{
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "category_name",
      "title": "Brief finding title",
      "description": "Detailed description of the vulnerability including what line(s) are affected",
      "remediation": "Specific steps to fix the issue with code example if helpful"
    }
  ]
}
```

## Rules:
- Only report findings you are **confident** about. Better to miss one than to report a false positive.
- Do NOT report style issues, performance suggestions, or best-practice nitpicks unless they have a clear security impact.
- Do NOT report "this looks fine" or "no issues found" as findings — just return an empty findings array.
- If you see the same vulnerability pattern repeated across a file, group them into one finding and mention the multiple locations.
- The JSON must be parseable. Do not include markdown code fences in your response — return pure JSON.
- Do not include any text outside the JSON object.

Analyze the code below and return ONLY the JSON object:"""


class Analyzer:
    def __init__(self, api_key: str, model: str = "deepseek-v4-pro", verbose: bool = False):
        self.client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
        self.model = model
        self.verbose = verbose

    def analyze_chunk(self, chunk_code: str) -> list[dict]:
        findings: list[dict] = []

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SECURITY_AUDIT_SYSTEM_PROMPT},
                        {"role": "user", "content": chunk_code},
                    ],
                    temperature=0.1,
                    max_tokens=4096,
                )

                raw = response.choices[0].message.content or ""
                raw = raw.strip()

                if raw.startswith("```"):
                    lines = raw.split("\n")
                    raw = "\n".join(lines[1:-1] if len(lines) > 2 else lines[1:])

                result = json.loads(raw)
                chunk_findings = result.get("findings", [])
                findings.extend(chunk_findings)
                break

            except json.JSONDecodeError:
                if self.verbose:
                    print(f"JSON parse error on attempt {attempt + 1}, raw response: {raw[:200]}...")
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except Exception as e:
                if self.verbose:
                    print(f"API error on attempt {attempt + 1}: {e}")
                if attempt < 2:
                    time.sleep(2 ** attempt)

        return findings
