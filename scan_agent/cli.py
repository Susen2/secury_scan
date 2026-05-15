import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn

from scan_agent.collector import collect_files
from scan_agent.chunker import estimate_tokens, chunk_files
from scan_agent.analyzer import Analyzer
from scan_agent.reporter import print_report, save_report
from scan_agent.skills import discover_skills, get_skill_map, SkillFinding


def _force_utf8() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _skill_finding_to_dict(f: SkillFinding) -> dict:
    return {
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "line": f.line,
        "file_path": f.file_path,
        "remediation": f.remediation,
        "evidence": f.evidence,
        "source": f.source,
    }


def _build_skill_context(findings: list[SkillFinding], target_file: str) -> str:
    relevant = [f for f in findings if target_file in f.file_path]
    if not relevant:
        return ""
    lines: list[str] = []
    lines.append("## Local Pre-Screening Findings (for context)")
    lines.append("The following issues were already flagged by local rule-based analysis for this file area. Use these as starting points for deeper investigation:")
    for f in relevant:
        lines.append(f"- [{f.severity.upper()}] Line {f.line}: {f.title} — {f.description[:200]}")
    return "\n".join(lines)


def main() -> None:
    _force_utf8()
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")

    skill_map = get_skill_map()
    all_skill_names = list(skill_map.keys())

    parser = argparse.ArgumentParser(
        prog="scan_agent",
        description="AI-powered Python security audit tool (DeepSeek LLM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python -m scan_agent /path/to/my_project
  python -m scan_agent /path/to/my_project --output results.json
  python -m scan_agent /path/to/my_project --exclude tests,migrations
  python -m scan_agent /path/to/my_project --skills secrets_detection,injection_detection
  python -m scan_agent /path/to/my_project --no-skills
  python -m scan_agent /path/to/my_project --skills-only

Available skills: {", ".join(all_skill_names)}
        """,
    )
    parser.add_argument("target", help="Path to the Python project to scan")
    parser.add_argument("-o", "--output", default="scan_report.json", help="Output JSON report path (default: scan_report.json)")
    parser.add_argument("-m", "--model", default=os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro"), help="DeepSeek model to use (default: deepseek-v4-pro)")
    parser.add_argument("-k", "--api-key", default=os.getenv("DEEPSEEK_API_KEY"), help="DeepSeek API key (default: from .env)")
    parser.add_argument("--exclude", default="", help="Comma-separated additional directories to exclude")
    parser.add_argument("--max-tokens", type=int, default=3000, help="Max tokens per API chunk (default: 3000)")
    parser.add_argument("--skills", default="all", help=f"Comma-separated skill names to run, or 'all' (default: all). Available: {', '.join(all_skill_names)}")
    parser.add_argument("--no-skills", action="store_true", help="Skip local rule-based pre-screening")
    parser.add_argument("--skills-only", action="store_true", help="Only run local skills, skip LLM analysis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.no_skills and args.skills_only:
        console = Console(stderr=True, safe_box=True)
        console.print("[red]Error: --no-skills and --skills-only cannot be used together.[/]")
        sys.exit(1)

    if args.skills_only and not args.api_key:
        pass
    elif not args.api_key and not args.skills_only:
        console = Console(stderr=True, safe_box=True)
        console.print("[red]Error: No API key provided. Set DEEPSEEK_API_KEY in .env or use --api-key.[/]")
        sys.exit(1)

    console = Console(safe_box=True)

    console.print()
    console.print("[bold cyan]╔══════════════════════════════════════════╗[/]")
    console.print("[bold cyan]║[/]   [bold white]AI Security Scanner (DeepSeek)[/]        [bold cyan]║[/]")
    console.print("[bold cyan]╚══════════════════════════════════════════╝[/]")
    console.print()

    target_path = os.path.abspath(args.target)
    console.print(f"[dim]Target:[/] {target_path}")
    console.print(f"[dim]Model: [/] {args.model}")
    console.print(f"[dim]Output:[/] {args.output}")

    if args.no_skills:
        console.print(f"[dim]Skills:[/] disabled")
    elif args.skills_only:
        selected_skills = all_skill_names
        console.print(f"[dim]Skills:[/] {', '.join(selected_skills)} (only — no LLM)")
    elif args.skills == "all":
        selected_skills = all_skill_names
        console.print(f"[dim]Skills:[/] {', '.join(selected_skills)}")
    else:
        selected_skills = [s.strip() for s in args.skills.split(",") if s.strip()]
        unknown = [s for s in selected_skills if s not in skill_map]
        if unknown:
            console.print(f"[yellow]Warning: Unknown skills ignored: {', '.join(unknown)}[/]")
        selected_skills = [s for s in selected_skills if s in skill_map]
        console.print(f"[dim]Skills:[/] {', '.join(selected_skills)}")
    console.print()

    exclude_set = set()
    if args.exclude:
        exclude_set = {d.strip() for d in args.exclude.split(",") if d.strip()}

    console.print("[bold]Step 1/5:[/] Collecting Python files...")
    try:
        files = collect_files(target_path, exclude_set)
    except (FileNotFoundError, NotADirectoryError) as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)

    if not files:
        console.print("[yellow]No Python files found. Nothing to scan.[/]")
        sys.exit(0)

    console.print(f"  Found [green]{len(files)}[/] Python file(s)")
    total_estimated_tokens = sum(estimate_tokens(content) for _, content in files)
    console.print(f"  Estimated [green]~{total_estimated_tokens}[/] tokens\n")

    all_findings: list[dict] = []

    use_skills = not args.no_skills and bool(selected_skills)
    all_skill_findings: list[SkillFinding] = []

    if use_skills:
        console.print("[bold]Step 2/5:[/] Running local skill pre-screening...")
        skill_instances = [skill_map[name] for name in selected_skills]

        for skill in skill_instances:
            findings = skill.analyze_files(files)
            if findings:
                console.print(f"  [dim]{skill.name}[/]: [yellow]{len(findings)}[/] finding(s)")
            all_skill_findings.extend(findings)

        console.print(f"  Local skills found [yellow]{len(all_skill_findings)}[/] total pre-screen finding(s)\n")

        skill_dicts = [_skill_finding_to_dict(f) for f in all_skill_findings]
        all_findings.extend(skill_dicts)

        if args.skills_only:
            console.print("[bold]Step 3/5:[/] Skipping LLM analysis (--skills-only)")
        else:
            step_label = "3/5"
    else:
        console.print("[bold]Step 2/5:[/] Skipping skills (--no-skills)\n")
        step_label = "2/5"

    llm_finding_count = 0

    if not args.skills_only:
        console.print(f"[bold]Step {step_label}:[/] Chunking for LLM analysis...")
        chunks = chunk_files(files, max_tokens=args.max_tokens)
        console.print(f"  Created [green]{len(chunks)}[/] chunk(s)\n")

        step_num = int(step_label.split("/")[0]) + 1
        console.print(f"[bold]Step {step_num}/5:[/] Analyzing with DeepSeek ({args.model})...")
        analyzer = Analyzer(api_key=args.api_key, model=args.model, verbose=args.verbose)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning", total=len(chunks))

            for i, chunk in enumerate(chunks):
                file_list = ", ".join(chunk.files[:3])
                if len(chunk.files) > 3:
                    file_list += f" (+{len(chunk.files) - 3} more)"
                progress.update(task, description=f"[dim]Chunk {i + 1}/{len(chunks)}: {file_list}[/]")

                code_to_analyze = chunk.code
                if use_skills and all_skill_findings:
                    context_parts: list[str] = []
                    for fpath in chunk.files:
                        ctx = _build_skill_context(all_skill_findings, fpath)
                        if ctx and ctx not in context_parts:
                            context_parts.append(ctx)
                    if context_parts:
                        code_to_analyze = (
                            "[SKILL PRE-SCREEN CONTEXT]\n"
                            + "\n\n".join(context_parts)
                            + "\n[/SKILL PRE-SCREEN CONTEXT]\n\n[CODE TO AUDIT]\n"
                            + chunk.code
                        )

                chunk_findings = analyzer.analyze_chunk(code_to_analyze)
                all_findings.extend(chunk_findings)
                llm_finding_count += len(chunk_findings)
                progress.advance(task)

        color = "red" if llm_finding_count else "green"
        console.print(f"  LLM analysis complete. [{color}]{llm_finding_count}[/] LLM finding(s)")

    total_steps = 5
    console.print(f"\n[bold]Step {total_steps}/{total_steps}:[/] Generating report...")
    save_report(all_findings, len(files), args.output)
    console.print(f"  JSON report saved to [bold]{args.output}[/]")

    print_report(all_findings, len(files), console)


if __name__ == "__main__":
    main()
