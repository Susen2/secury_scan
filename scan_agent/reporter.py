import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

SEVERITY_COLORS = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

SEVERITY_LABELS = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
    "info": "[INFO]",
}


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def print_report(findings: list[dict], scanned_files: int, console: Console) -> None:
    total = len(findings)
    console.print()
    console.print(Panel(Text("Security Scan Report", style="bold white"), expand=False))
    console.print(f"Scanned [bold cyan]{scanned_files}[/] files · Found [bold red]{total}[/] findings\n")

    if total == 0:
        console.print(Panel("[OK] No security issues detected!", style="green"))
        return

    counts = _count_by_severity(findings)
    sev_order = ["critical", "high", "medium", "low", "info"]

    table = Table(title="Summary by Severity", box=box.SIMPLE)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in sev_order:
        if sev in counts:
            label = SEVERITY_LABELS.get(sev, "")
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(f"{label} {sev.upper()}", str(counts[sev]), style=color)
    console.print(table)
    console.print()

    for sev in sev_order:
        matching = [f for f in findings if f.get("severity", "info").lower() == sev]
        if not matching:
            continue

        label = SEVERITY_LABELS.get(sev, "•")
        color = SEVERITY_COLORS.get(sev, "white")
        console.print(Text(f"{label} {sev.upper()} ({len(matching)})", style=f"bold {color}"))
        console.print()

        for i, finding in enumerate(matching):
            title = finding.get("title", "Untitled")
            category = finding.get("category", "unknown")
            desc = finding.get("description", "")
            remediation = finding.get("remediation", "")
            file_path = finding.get("file_path", "")
            line = finding.get("line", 0)
            evidence = finding.get("evidence", "")
            source = finding.get("source", "")

            source_tag = " [dim][local][/]" if source == "local_rule" else ""
            console.print(f"  [{color}]▸ {title}[/]{source_tag}")

            if file_path and line:
                console.print(f"    Location: [dim]{file_path}:{line}[/]")
            elif file_path:
                console.print(f"    Location: [dim]{file_path}[/]")
            elif line:
                console.print(f"    Line: [dim]{line}[/]")
            console.print(f"    Category: [dim]{category}[/]")
            if evidence:
                console.print(f"    Evidence: [dim italic]{evidence}[/]")
            if desc:
                console.print(f"    {desc}")
            if remediation:
                console.print(f"    [green]Fix: {remediation}[/]")
            console.print()

            if i < len(matching) - 1:
                console.print("  ─" * 30)


def save_report(findings: list[dict], scanned_files: int, output_path: str) -> None:
    report = {
        "generated_at": datetime.now().isoformat(),
        "scanned_files": scanned_files,
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
