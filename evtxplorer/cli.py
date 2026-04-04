"""
EVTXplorer CLI entry point.

Usage:
    evtxplorer --input security.evtx --rules rules/ --format html --output report.html
    evtxplorer --input logs/ --rules rules/ --format json --output findings.json
    evtxplorer --input security.xml  # defaults: rules/ dir, stdout JSON
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text
from rich import box

from evtxplorer import __version__
from evtxplorer.engine import DetectionEngine, Finding, SEVERITY_ORDER, load_rules
from evtxplorer.parser import parse_file
from evtxplorer.reporter import build_summary, write_json, write_csv, write_html

console = Console(stderr=True)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "info":     "blue",
}


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


def _collect_inputs(paths: list[str]) -> list[Path]:
    """Expand directories and glob patterns into a list of files."""
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for ext in ("*.evtx", "*.xml", "*.txt"):
                files.extend(sorted(p.glob(ext)))
        elif p.exists():
            files.append(p)
        else:
            console.print(f"[yellow]Warning:[/] input not found: {raw}")
    return files


def _print_summary_table(findings: list[Finding], events_parsed: int):
    console.print()
    console.rule("[bold]EVTXplorer Results[/]")
    console.print(f"  Events parsed : [cyan]{events_parsed:,}[/]")
    console.print(f"  Total findings: [cyan]{len(findings):,}[/]")
    console.print()

    if not findings:
        console.print("  [green]No detections fired.[/]")
        return

    # Severity breakdown
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.rule.severity] = counts.get(f.rule.severity, 0) + 1

    sev_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            color = SEVERITY_COLORS.get(sev, "white")
            sev_table.add_row(
                Text(sev.upper(), style=f"bold {color}"),
                Text(str(counts[sev]), style=color),
            )
    console.print(sev_table)

    # Finding detail table
    tbl = Table(
        "Severity", "Rule", "MITRE", "Computer", "Event ID", "Timestamp",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=True,
    )
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.rule.severity), f.timestamp),
    )
    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f.rule.severity, "white")
        tbl.add_row(
            Text(f.rule.severity.upper(), style=f"bold {color}"),
            f.rule.name,
            f.rule.mitre_id or "—",
            f.computer or "—",
            str(f.event_id),
            (f.timestamp[:19].replace("T", " ") if f.timestamp else "—"),
        )
    console.print(tbl)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="evtxplorer",
        description="Windows Event Log analyzer with MITRE ATT&CK detection rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  evtxplorer --input security.evtx
  evtxplorer --input logs/ --rules custom_rules/ --format html --output report.html
  evtxplorer --input security.evtx system.evtx --format json --output findings.json
  evtxplorer --input security.xml --severity high critical
        """,
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True, metavar="PATH",
        help="Event log file(s) or directory (.evtx, .xml, .txt)",
    )
    parser.add_argument(
        "--rules", "-r", default="rules", metavar="DIR",
        help="Directory containing YAML rule files (default: ./rules)",
    )
    parser.add_argument(
        "--format", "-f", choices=["json", "csv", "html", "none"], default="none",
        help="Output format (default: none — print to terminal only)",
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Output file path (required for json/csv/html)",
    )
    parser.add_argument(
        "--severity", "-s", nargs="+",
        choices=SEVERITY_ORDER, metavar="LEVEL",
        help="Filter findings to specific severity levels",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--version", action="version", version=f"EVTXplorer {__version__}",
    )

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    # Validate output arg
    if args.format != "none" and not args.output:
        parser.error(f"--output is required when --format is {args.format}")

    # Load rules
    rules_dir = Path(args.rules)
    if not rules_dir.is_dir():
        console.print(f"[red]Rules directory not found:[/] {rules_dir}")
        sys.exit(1)

    rules = load_rules(rules_dir)
    if not rules:
        console.print(f"[yellow]No rules loaded from {rules_dir}[/]")
        sys.exit(1)

    console.print(f"[cyan]EVTXplorer {__version__}[/] — {len(rules)} rules loaded")

    # Collect input files
    input_files = _collect_inputs(args.input)
    if not input_files:
        console.print("[red]No input files found.[/]")
        sys.exit(1)

    console.print(f"Analyzing [cyan]{len(input_files)}[/] file(s)...")

    # Run analysis
    engine = DetectionEngine(rules)
    all_findings: list[Finding] = []
    total_events = 0

    for path in input_files:
        file_events = 0
        try:
            for event in parse_file(path):
                file_events += 1
                hits = engine.evaluate(event)
                all_findings.extend(hits)
        except Exception as exc:
            console.print(f"[red]Error parsing {path}:[/] {exc}")
            continue
        total_events += file_events
        console.print(f"  [dim]{path.name}[/] — {file_events:,} events")

    # Flush threshold findings
    all_findings.extend(engine.flush())

    # Severity filter
    if args.severity:
        all_findings = [f for f in all_findings if f.rule.severity in args.severity]

    # Sort: most severe first, then chronological
    all_findings.sort(
        key=lambda f: (SEVERITY_ORDER.index(f.rule.severity), f.timestamp)
    )

    # Print terminal summary
    _print_summary_table(all_findings, total_events)

    # Write output
    if args.format != "none":
        out_path = Path(args.output)
        summary = build_summary(
            all_findings,
            source_files=[str(p) for p in input_files],
            total_events=total_events,
        )
        if args.format == "json":
            write_json(all_findings, summary, out_path)
        elif args.format == "csv":
            write_csv(all_findings, out_path)
        elif args.format == "html":
            write_html(all_findings, summary, out_path)
        console.print(f"\n[green]Report written:[/] {out_path}")

    sys.exit(0 if not all_findings else 1)


if __name__ == "__main__":
    main()
