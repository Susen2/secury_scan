# scan_agent

AI-powered Python security audit tool that combines local rule-based pattern matching with DeepSeek LLM deep analysis to produce comprehensive security scan reports.

## Architecture

The scanning pipeline runs in 5 stages:

1. **File Collection** — Recursively collects all `.py` files, excluding `venv`, `.git`, `__pycache__`, etc.
2. **Local Skill Pre-Screening** — 5 regex-based skills perform fast deterministic checks
3. **Code Chunking** — Files are split into token-budgeted chunks for the LLM
4. **LLM Deep Analysis** — Code chunks are sent to DeepSeek API for contextual security review
5. **Reporting** — Results rendered as colored terminal tables and saved as JSON

## Built-in Skills

| Skill | Detects |
|---|---|
| `secrets_detection` | Hardcoded API keys, passwords, JWT secrets, tokens |
| `injection_detection` | `eval`/`exec` injection, SQL injection, command injection, insecure deserialization, SSRF |
| `fastapi_security` | CORS misconfig, debug mode, path traversal, error disclosure, file upload issues |
| `auth_security` | Weak hashes (MD5/SHA1), insecure random, JWT misconfig, timing-based enumeration |
| `file_security` | World-writable permissions, path traversal, unsafe file deletion, async file ops |

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env  # then edit .env with your DeepSeek API key
```

## Usage

```bash
# Full scan (skills + LLM)
python -m scan_agent /path/to/project

# Custom output path
python -m scan_agent /path/to/project -o results.json

# Exclude directories
python -m scan_agent /path/to/project --exclude tests,migrations

# Run specific skills only
python -m scan_agent /path/to/project --skills secrets_detection,injection_detection

# Skills only (no LLM)
python -m scan_agent /path/to/project --skills-only

# LLM only (no skills)
python -m scan_agent /path/to/project --no-skills
```

## Configuration

| CLI Flag | Env Variable | Default |
|---|---|---|
| `-k, --api-key` | `DEEPSEEK_API_KEY` | — |
| `-m, --model` | `DEEPSEEK_MODEL` | `deepseek-v4-pro` |
| `--max-tokens` | — | `3000` |
| `-o, --output` | — | `scan_report.json` |

## Requirements

- Python 3.10+
- DeepSeek API key
