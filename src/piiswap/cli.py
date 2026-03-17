"""CLI interface for piiswap."""

import csv
import os
import sys
from pathlib import Path
from typing import List

import click

from piiswap import __version__


def _hint(lines: list) -> None:
    """Print next-step hints after a command completes."""
    click.echo("")
    click.echo("Next steps:")
    for line in lines:
        click.echo(f"  {line}")


def _get_default_db_path(case_id: str) -> Path:
    """Default mapping DB path: .piiswap/<case_id>.db in current directory."""
    return Path(".piiswap") / f"{case_id}.db"


def _get_case_id(case_id: str = None) -> str:
    """Determine case ID from argument or current directory name."""
    if case_id:
        return case_id
    return Path.cwd().name


@click.group()
@click.version_option(__version__, prog_name="piiswap")
def main():
    """PiiSwap: Bidirectional anonymization for DFIR case data."""
    pass


@main.command()
@click.argument("case_id", required=False)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None,
              help="Encryption password (or env: PIISWAP_KEY)")
def init(case_id, password):
    """Initialize mapping database for a case."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with MappingStore(db_path, password=password) as store:
        pass  # Opening creates schema

    click.echo(f"Initialized mapping database for {case_id}")
    click.echo(f"Database: {db_path.resolve()}")
    if password:
        click.echo("Database is encrypted.")
    else:
        click.echo("WARNING: Database is NOT encrypted. Use --password for encryption.")

    _hint([
        "piiswap scan <path> -r                     Scan files for PII (dry-run)",
        "piiswap allowlist import-file iocs.txt      Import IOCs to protect from anonymization",
        "piiswap allowlist add-domain <domain>        Protect a domain and its emails",
    ])


@main.command()
@click.argument("case_id")
@click.option("--base-dir", "-d", type=click.Path(), default=".",
              help="Parent directory where the case folder will be created (default: current dir)")
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None,
              help="Encryption password (or env: PIISWAP_KEY)")
def new(case_id, base_dir, password):
    """Create a new case directory with standard structure and init the database.

    Example: piiswap new CASE-2026-050
    """
    from piiswap.store.database import MappingStore

    base = Path(base_dir)
    case_dir = base / case_id

    if case_dir.exists():
        click.echo(f"Error: Directory {case_dir} already exists.", err=True)
        sys.exit(1)

    # Create directory structure
    subdirs = [
        "evidence",           # Drop provider/evidence files here
        "evidence_anon",      # Anonymized output (auto-generated)
        "iocs",               # IOC files for allowlist import
        "llm_output",         # Save LLM analysis results here
        "restored",           # De-anonymized reports (auto-generated)
    ]
    for sub in subdirs:
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    # Initialize mapping database
    db_path = case_dir / ".piiswap" / f"{case_id}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with MappingStore(db_path, password=password) as store:
        pass

    # Write a quickstart README inside the case
    quickstart = case_dir / "README.md"
    quickstart.write_text(
        f"# {case_id}\n\n"
        "## Quick start\n\n"
        "```bash\n"
        f"cd {case_id}\n\n"
        "# 1. Drop your evidence files into evidence/\n\n"
        "# 2. (Optional) Add IOC files to iocs/\n"
        "piiswap allowlist import-file iocs/my_iocs.txt --type ioc\n\n"
        "# 3. Scan for PII\n"
        "piiswap scan evidence/ -r\n\n"
        "# 4. Anonymize\n"
        "piiswap anonymize evidence/ -r -o evidence_anon/\n\n"
        "# 5. Send evidence_anon/ to your LLM, save result in llm_output/\n\n"
        "# 6. De-anonymize the LLM report\n"
        "piiswap deanonymize llm_output/ -r -o restored/\n"
        "```\n",
        encoding="utf-8",
    )

    click.echo(f"Created case: {case_dir.resolve()}")
    click.echo(f"")
    click.echo(f"  {case_id}/")
    click.echo(f"  +-- evidence/          <- drop your files here")
    click.echo(f"  +-- evidence_anon/     <- anonymized output")
    click.echo(f"  +-- iocs/              <- IOC files for allowlist")
    click.echo(f"  +-- llm_output/        <- save LLM results here")
    click.echo(f"  +-- restored/          <- de-anonymized reports")
    click.echo(f"  +-- .piiswap/          <- mapping database")
    click.echo(f"  +-- README.md          <- quick start guide")
    click.echo(f"")
    if password:
        click.echo("Database is encrypted.")
    else:
        click.echo("Database is NOT encrypted. Use -p for encryption.")
    _hint([
        f"cd {case_id}",
        "1. Copy your evidence files into evidence/",
        "2. (Optional) Add IOC files to iocs/ and run:",
        "   piiswap allowlist import-file iocs/my_iocs.txt --type ioc",
        "3. piiswap scan evidence/ -r                Scan for PII (dry-run)",
    ])


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output path (default: <input>_anon)")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
@click.option("--recursive", "-r", is_flag=True, default=False)
@click.option("--strict", is_flag=True, default=False,
              help="Only anonymize full name pairs (firstname + lastname)")
@click.option("--dry-run", is_flag=True, default=False,
              help="Show what would be anonymized without making changes")
@click.option("--ioc-file", type=click.Path(exists=True), default=None,
              help="Path to a file of IOC values (one per line) to protect from anonymization")
@click.option("--include-types", default=None,
              help="Comma-separated PII types to include (e.g. email,phone). "
                   "All other types are ignored.")
@click.option("--exclude-types", default=None,
              help="Comma-separated PII types to skip (e.g. hostname,filepath_user).")
@click.option("--pii-columns", default=None,
              help="Comma-separated column names to anonymize (CSV/Excel only). "
                   "Overrides --keep-columns when both are given.")
@click.option("--keep-columns", default=None,
              help="Comma-separated column names to keep unchanged (CSV/Excel only). "
                   "All other columns will be anonymized.")
@click.option("--template", "template_name", default=None,
              help="Provider template for automatic column configuration (e.g. microsoft-signin). "
                   "Explicit --pii-columns/--keep-columns always override the template.")
def anonymize(input_path, output, case_id, password, recursive, strict, dry_run, ioc_file,
              include_types, exclude_types, pii_columns, keep_columns, template_name):
    """Anonymize file(s) — replace PII with tokens."""
    from piiswap.core.engine import AnonymizationEngine
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    if not db_path.exists():
        click.echo(f"Error: No database found for {case_id}. Run 'piiswap init' first.", err=True)
        sys.exit(1)

    input_path = Path(input_path)

    # Determine output path
    if output:
        output_path = Path(output)
    elif input_path.is_dir():
        output_path = input_path.parent / f"{input_path.name}_anon"
    else:
        output_path = input_path.parent / f"{input_path.stem}_anon{input_path.suffix}"

    with MappingStore(db_path, password=password) as store:
        # Import IOC allowlist values before building the engine so the filter
        # is aware of them from the first pass.
        if ioc_file:
            ioc_values = _parse_value_file(Path(ioc_file))
            for ioc in ioc_values:
                store.add_allowlist(ioc, "ioc", case_id, "auto-imported from IOC file")
            click.echo(f"Imported {len(ioc_values)} IOC value(s) from {ioc_file}")

        include_list = [t.strip() for t in include_types.split(",")] if include_types else None
        exclude_list = [t.strip() for t in exclude_types.split(",")] if exclude_types else None
        pii_col_list = _parse_columns(pii_columns)
        keep_col_list = _parse_columns(keep_columns)

        # Apply provider template when requested; explicit flags take priority.
        if template_name:
            from piiswap.templates import get_template, list_templates
            tmpl = get_template(template_name)
            if not tmpl:
                available = ", ".join(name for name, _ in list_templates())
                click.echo(
                    f"Unknown template '{template_name}'. Available: {available}", err=True
                )
                sys.exit(1)
            click.echo(f"Using template: {template_name} ({tmpl['description']})")
            if not pii_col_list:
                pii_col_list = tmpl.get("pii_columns", [])
            if not keep_col_list:
                keep_col_list = tmpl.get("keep_columns", [])

        engine = _build_engine(store, case_id, strict,
                               include_types=include_list, exclude_types=exclude_list,
                               pii_columns=pii_col_list, keep_columns=keep_col_list)

        if dry_run:
            _run_scan(engine, input_path, recursive)
            return

        if input_path.is_dir():
            results = engine.anonymize_directory(input_path, output_path, recursive=recursive)
        else:
            results = [engine.anonymize_file(input_path, output_path)]

        # Print results
        for r in results:
            status = r["status"]
            if status == "anonymized":
                click.echo(f"  [OK] {r['file']} -> {r['output']}")
            elif status == "skipped":
                click.echo(f"  [SKIP] {r['file']}: {r.get('reason', '')}")

        stats = store.stats(case_id)
        click.echo(f"\nMappings: {stats['total_mappings']} | "
                    f"Entities: {stats['total_entities']} | "
                    f"Files: {stats['processed_files']}")

        _hint([
            f"piiswap verify <original> {output_path}    Check for PII leaks",
            "piiswap mappings                            Review all token mappings",
            "piiswap status                              Show case statistics",
            "",
            "Share the anonymized files with your LLM for analysis.",
            "Save the LLM output, then de-anonymize:",
            f"piiswap deanonymize llm_output/ -r -o restored/",
        ])


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
@click.option("--recursive", "-r", is_flag=True, default=False)
@click.option("--only", default=None,
              help="Comma-separated PII types to restore (e.g. email,phone). "
                   "Tokens for all other types are left as-is.")
@click.option("--pii-columns", default=None,
              help="Comma-separated column names to de-anonymize (CSV/Excel only). "
                   "Overrides --keep-columns when both are given.")
@click.option("--keep-columns", default=None,
              help="Comma-separated column names to keep unchanged (CSV/Excel only). "
                   "All other columns will be de-anonymized.")
def deanonymize(input_path, output, case_id, password, recursive, only,
                pii_columns, keep_columns):
    """De-anonymize file(s) — restore tokens to original PII."""
    from piiswap.core.engine import AnonymizationEngine
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    if not db_path.exists():
        click.echo(f"Error: No database found for {case_id}.", err=True)
        sys.exit(1)

    only_list = [t.strip() for t in only.split(",")] if only else None
    pii_col_list = _parse_columns(pii_columns)
    keep_col_list = _parse_columns(keep_columns)

    input_path = Path(input_path)
    if output:
        output_path = Path(output)
    elif input_path.is_dir():
        output_path = input_path.parent / f"{input_path.name}_restored"
    else:
        output_path = input_path.parent / f"{input_path.stem}_restored{input_path.suffix}"

    with MappingStore(db_path, password=password) as store:
        engine = _build_engine(store, case_id,
                               pii_columns=pii_col_list, keep_columns=keep_col_list)

        if input_path.is_dir():
            results = engine.deanonymize_directory(
                input_path, output_path, recursive=recursive, only_types=only_list
            )
        else:
            results = [engine.deanonymize_file(input_path, output_path, only_types=only_list)]

        for r in results:
            status = r["status"]
            if status == "deanonymized":
                click.echo(f"  [OK] {r['file']} -> {r['output']}")
            else:
                click.echo(f"  [SKIP] {r['file']}: {r.get('reason', '')}")

        hints = [f"Your restored files are in: {output_path}"]
        if not only:
            hints.append("")
            hints.append("Want to restore only specific PII types? Use --only:")
            hints.append("  piiswap deanonymize <path> --only email,username")
            hints.append("  (passwords, IBANs, etc. stay masked - safe for sharing)")
        hints.append("")
        hints.append("piiswap mappings                  Review all token mappings")
        _hint(hints)


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
@click.option("--recursive", "-r", is_flag=True, default=False)
@click.option("--strict", is_flag=True, default=False)
@click.option("--ioc-file", type=click.Path(exists=True), default=None,
              help="Path to a file of IOC values (one per line) to protect from anonymization")
@click.option("--include-types", default=None,
              help="Comma-separated PII types to include (e.g. email,phone). "
                   "All other types are ignored.")
@click.option("--exclude-types", default=None,
              help="Comma-separated PII types to skip (e.g. hostname,filepath_user).")
@click.option("--template", "template_name", default=None,
              help="Provider template for automatic column configuration (e.g. isp-connection). "
                   "Explicit --pii-columns/--keep-columns always override the template.")
def scan(input_path, case_id, password, recursive, strict, ioc_file, include_types, exclude_types,
         template_name):
    """Dry-run: show what PII would be detected without changing anything."""
    from piiswap.core.engine import AnonymizationEngine
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    if not db_path.exists():
        click.echo(f"Error: No database found for {case_id}. Run 'piiswap init' first.", err=True)
        sys.exit(1)

    input_path = Path(input_path)

    with MappingStore(db_path, password=password) as store:
        if ioc_file:
            ioc_values = _parse_value_file(Path(ioc_file))
            for ioc in ioc_values:
                store.add_allowlist(ioc, "ioc", case_id, "auto-imported from IOC file")
            click.echo(f"Imported {len(ioc_values)} IOC value(s) from {ioc_file}")

        include_list = [t.strip() for t in include_types.split(",")] if include_types else None
        exclude_list = [t.strip() for t in exclude_types.split(",")] if exclude_types else None

        pii_col_list: List[str] = []
        keep_col_list: List[str] = []

        # Apply provider template when requested.
        if template_name:
            from piiswap.templates import get_template, list_templates
            tmpl = get_template(template_name)
            if not tmpl:
                available = ", ".join(name for name, _ in list_templates())
                click.echo(
                    f"Unknown template '{template_name}'. Available: {available}", err=True
                )
                sys.exit(1)
            click.echo(f"Using template: {template_name} ({tmpl['description']})")
            pii_col_list = tmpl.get("pii_columns", [])
            keep_col_list = tmpl.get("keep_columns", [])

        engine = _build_engine(store, case_id, strict,
                               include_types=include_list, exclude_types=exclude_list,
                               pii_columns=pii_col_list, keep_columns=keep_col_list)
        _run_scan(engine, input_path, recursive)


@main.command()
@click.argument("original", type=click.Path(exists=True))
@click.argument("anonymized", type=click.Path(exists=True))
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def verify(original, anonymized, case_id, password):
    """Verify that no PII leaked into the anonymized file."""
    from piiswap.core.engine import AnonymizationEngine
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        engine = _build_engine(store, case_id)
        leaks = engine.verify(Path(original), Path(anonymized))

        if leaks:
            click.echo(f"FOUND {len(leaks)} PII LEAK(S):", err=True)
            for leak in leaks:
                click.echo(f"  {leak}", err=True)
            _hint([
                "PII leaks found! Options:",
                "  piiswap allowlist list                  Check if values should be allowlisted",
                "  Re-run anonymize to fix the leaks",
            ])
            sys.exit(1)
        else:
            click.echo("Verification passed: no PII leaks detected.")
            _hint([
                "The anonymized files are safe to share.",
                "Send them to your LLM for analysis, then de-anonymize the results:",
                "  piiswap deanonymize <llm_output> -o <restored>",
            ])


@main.command()
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def status(case_id, password):
    """Show mapping statistics for a case."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    if not db_path.exists():
        click.echo(f"No database found for {case_id}.")
        return

    with MappingStore(db_path, password=password) as store:
        stats = store.stats(case_id)
        click.echo(f"Case: {stats['case_id']}")
        click.echo(f"Total mappings: {stats['total_mappings']}")
        click.echo(f"Total entities: {stats['total_entities']}")
        click.echo(f"Processed files: {stats['processed_files']}")
        click.echo(f"Allowlist entries: {stats['allowlist_entries']}")
        if stats["by_type"]:
            click.echo("\nMappings by type:")
            for pii_type, count in sorted(stats["by_type"].items()):
                click.echo(f"  {pii_type}: {count}")

        hints = ["piiswap mappings                  View all token-to-PII mappings"]
        if stats["total_mappings"] == 0:
            hints.insert(0, "No mappings yet. Start by scanning your evidence:")
            hints.insert(1, "  piiswap scan evidence/ -r")
        else:
            hints.append("piiswap link <token1> <token2>    Merge two entities manually")
            hints.append("piiswap allowlist list            View protected values")
        _hint(hints)


@main.command()
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def mappings(case_id, password):
    """List all PII-to-token mappings."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        all_mappings = store.get_all_mappings(case_id)
        if not all_mappings:
            click.echo("No mappings found.")
            return

        click.echo(f"{'Entity':<12} {'Type':<14} {'Token':<16} {'Raw Value'}")
        click.echo("-" * 70)
        for m in all_mappings:
            raw = m["raw_value"]
            if len(raw) > 40:
                raw = raw[:37] + "..."
            click.echo(f"{m['entity_id']:<12} {m['pii_type']:<14} {m['token']:<16} {raw}")


# --- Allowlist subcommands ---

@main.group()
def allowlist():
    """Manage the allowlist (values that should never be anonymized)."""
    pass


@allowlist.command("add")
@click.argument("value")
@click.option("--type", "value_type", default="custom", help="Type: domain, alias, hostname, custom")
@click.option("--reason", default="", help="Why this value is allowlisted")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def allowlist_add(value, value_type, reason, case_id, password):
    """Add a value to the allowlist."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        store.add_allowlist(value, value_type, case_id, reason)
        click.echo(f"Added '{value}' ({value_type}) to allowlist for {case_id}")

    _hint([
        "piiswap scan <path> -r                     Re-scan to see the effect",
        "piiswap allowlist list                      View all allowlisted values",
        "piiswap allowlist add-domain <domain>       Protect a domain + its emails",
        "piiswap allowlist import-file <file>        Bulk import from file",
    ])


@allowlist.command("list")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def allowlist_list(case_id, password):
    """Show allowlist entries."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        entries = store.get_allowlist(case_id)
        if not entries:
            click.echo("Allowlist is empty.")
            return
        click.echo(f"{'Value':<30} {'Type':<12} {'Reason'}")
        click.echo("-" * 60)
        for e in entries:
            click.echo(f"{e['value']:<30} {e['value_type']:<12} {e.get('reason', '')}")


@allowlist.command("remove")
@click.argument("value")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def allowlist_remove(value, case_id, password):
    """Remove a value from the allowlist."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        store.remove_allowlist(value, case_id)
        click.echo(f"Removed '{value}' from allowlist")


@allowlist.command("add-domain")
@click.argument("domain")
@click.option("--reason", default="", help="Why this domain is allowlisted")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def allowlist_add_domain(domain, reason, case_id, password):
    """Add a domain to the allowlist — protects the domain itself, all its subdomains,
    and all email addresses on that domain from being anonymized."""
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    normalized = domain.lower().lstrip("@").strip()

    with MappingStore(db_path, password=password) as store:
        store.add_allowlist(normalized, "domain", case_id, reason)
        click.echo(f"Added domain '{normalized}' to allowlist for {case_id}")
        click.echo(f"  Emails on @{normalized} will also be protected.")
        click.echo(f"  Hostnames ending in .{normalized} will also be protected.")

    _hint([
        "piiswap scan <path> -r                     Re-scan to verify the effect",
        "piiswap allowlist list                      View all allowlisted values",
    ])


@allowlist.command("import-file")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--type", "value_type", default="custom",
              help="Value type for all imported entries (e.g. domain, hostname, ioc, custom)")
@click.option("--reason", default="", help="Reason stored for every imported entry")
@click.option("--column", default=0, show_default=True,
              help="Column index to read from CSV files (0-based)")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def allowlist_import_file(file_path, value_type, reason, column, case_id, password):
    """Bulk-import allowlist values from a plain-text file or CSV.

    Each non-empty, non-comment line (lines not starting with #) is added as
    one allowlist entry.  For CSV files use --column to pick which column to
    read (default: first column).
    """
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    values = _parse_value_file(Path(file_path), column=column)
    if not values:
        click.echo("No values found in file.", err=True)
        return

    with MappingStore(db_path, password=password) as store:
        for value in values:
            store.add_allowlist(value, value_type, case_id, reason)

    click.echo(f"Imported {len(values)} value(s) ({value_type}) into allowlist for {case_id}")

    _hint([
        "piiswap allowlist list                      Review imported values",
        "piiswap scan <path> -r                     Re-scan to see the effect",
        "piiswap anonymize <path> -r -o <output>    Ready to anonymize",
    ])


# --- Link command ---

@main.command()
@click.argument("token1")
@click.argument("token2")
@click.option("--case-id", "-c", default=None)
@click.option("--password", "-p", envvar="PIISWAP_KEY", default=None)
def link(token1, token2, case_id, password):
    """Manually link two entities (merge token2 into token1's entity)."""
    from piiswap.core.resolver import EntityResolver
    from piiswap.store.database import MappingStore

    case_id = _get_case_id(case_id)
    db_path = _get_default_db_path(case_id)

    with MappingStore(db_path, password=password) as store:
        m1 = store.get_mapping_by_token(token1, case_id)
        m2 = store.get_mapping_by_token(token2, case_id)

        if not m1:
            click.echo(f"Token {token1} not found.", err=True)
            sys.exit(1)
        if not m2:
            click.echo(f"Token {token2} not found.", err=True)
            sys.exit(1)

        resolver = EntityResolver(store, case_id)
        resolver.link_entities(m1["entity_id"], m2["entity_id"])
        click.echo(f"Linked {token2} ({m2['entity_id']}) into {token1} ({m1['entity_id']})")

    _hint([
        "piiswap mappings                            Review updated mappings",
    ])


# --- Templates command ---

@main.command()
def templates():
    """List available provider data templates."""
    from piiswap.templates import list_templates

    click.echo("Available templates:\n")
    click.echo(f"  {'Name':<22} Description")
    click.echo(f"  {'-' * 22} {'-' * 50}")
    for name, desc in list_templates():
        click.echo(f"  {name:<22} {desc}")

    click.echo("\nUsage:")
    click.echo("  piiswap anonymize data.csv --template microsoft-signin")
    click.echo("  piiswap scan data.csv --template isp-connection")


# --- Helpers ---

def _parse_columns(raw: str) -> List[str]:
    """Parse a comma-separated column name string into a list.

    Returns an empty list (falsy) when ``raw`` is None or blank, so callers
    can use a simple truthiness check to detect "no column filter specified".

    Args:
        raw: Raw CLI string, e.g. ``"email,name,phone"`` or None.

    Returns:
        List of stripped, non-empty column name strings.
    """
    if not raw:
        return []
    return [c.strip() for c in raw.split(",") if c.strip()]


def _parse_value_file(path: Path, column: int = 0) -> List[str]:
    """Parse a flat file or CSV and return a list of non-empty, non-comment values.

    Args:
        path: Path to the file (.csv handled specially; all other extensions
              are treated as one-value-per-line plain text).
        column: For CSV files, which column index to read (0-based).

    Returns:
        Deduplicated list of stripped string values.
    """
    values: List[str] = []
    with open(path, newline="", encoding="utf-8") as fh:
        if path.suffix.lower() == ".csv":
            reader = csv.reader(fh)
            for row in reader:
                if not row:
                    continue
                try:
                    cell = row[column].strip()
                except IndexError:
                    continue
                if cell and not cell.startswith("#"):
                    values.append(cell)
        else:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    values.append(line)
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _build_engine(store, case_id, strict=False, include_types=None, exclude_types=None,
                  pii_columns=None, keep_columns=None):
    """Build engine, optionally loading name/address detectors.

    Args:
        store: Open MappingStore instance.
        case_id: Active case identifier.
        strict: If True, only match full name pairs (firstname + lastname).
        include_types: If provided, only detect/anonymize these PII types.
        exclude_types: If provided, skip detection for these PII types.
        pii_columns: Column names to anonymize (CSV/Excel column-aware mode).
        keep_columns: Column names to keep unchanged (CSV/Excel column-aware mode).
    """
    from piiswap.core.engine import AnonymizationEngine

    name_detector = None
    address_detector = None

    # Try loading wordlist detectors
    try:
        from piiswap.detectors.name import NameDetector
        name_detector = NameDetector(strict=strict)
    except Exception:
        pass

    try:
        from piiswap.detectors.address import AddressDetector
        address_detector = AddressDetector()
    except Exception:
        pass

    return AnonymizationEngine(
        store=store,
        case_id=case_id,
        strict_names=strict,
        name_detector=name_detector,
        address_detector=address_detector,
        include_types=include_types,
        exclude_types=exclude_types,
        pii_columns=pii_columns,
        keep_columns=keep_columns,
    )


def _run_scan(engine, input_path, recursive):
    """Run PII scan and display results."""
    from piiswap.adapters.base import get_adapter

    files = []
    if input_path.is_dir():
        pattern = "**/*" if recursive else "*"
        files = [f for f in sorted(input_path.glob(pattern)) if f.is_file()]
    else:
        files = [input_path]

    total_matches = 0
    for fpath in files:
        adapter = get_adapter(fpath)
        if adapter is None:
            continue

        text = adapter.read(fpath)
        matches = engine.scan_text(text)

        if matches:
            click.echo(f"\n{fpath}:")
            for m in matches:
                # Show context
                ctx_start = max(0, m.start - 20)
                ctx_end = min(len(text), m.end + 20)
                context = text[ctx_start:ctx_end].replace("\n", " ")
                click.echo(f"  [{m.pii_type:<14}] '{m.raw_value}' (conf={m.confidence:.2f})")
                click.echo(f"                   ...{context}...")
            total_matches += len(matches)

    click.echo(f"\nTotal: {total_matches} PII matches in {len(files)} files")

    if total_matches > 0:
        _hint([
            "piiswap anonymize <path> -r -o <output>    Anonymize the files",
            "piiswap allowlist add <value>               Exclude a false positive",
            "piiswap allowlist add-domain <domain>       Protect a domain + its emails",
            "piiswap scan <path> -r --exclude-types <t>  Skip specific PII types",
            "piiswap scan <path> -r --ioc-file <file>    Protect IOCs during scan",
            "piiswap templates                           List provider data templates",
        ])
    else:
        _hint([
            "No PII found. If this is unexpected, check:",
            "  - Is the file format supported? (piiswap --help)",
            "  - Are you using --include-types to filter too aggressively?",
            "  - Try without --strict for broader name detection",
        ])
