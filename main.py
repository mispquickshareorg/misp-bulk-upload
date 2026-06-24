#!/usr/bin/env python3
"""Bulk upload DDoS events to MISP from a CSV file."""

import sys
import os
import logging
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv
from rich.console import Console

from misp_client import MISPClient, MISPConnectionError

console = Console()


def load_config(env_file: Optional[str] = None):
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()

    url = os.environ.get("MISP_URL", "").strip()
    api_key = os.environ.get("MISP_API_KEY", "").strip()
    verify_ssl = os.environ.get("MISP_VERIFY_SSL", "true").strip().lower() not in ("false", "0", "no", "off")
    try:
        timeout = int(os.environ.get("MISP_TIMEOUT", "30").strip())
    except ValueError:
        timeout = 30

    if not url:
        console.print("[red]ERROR: MISP_URL is not set. Copy .env.example to .env.[/red]")
        sys.exit(1)
    if not api_key:
        console.print("[red]ERROR: MISP_API_KEY is not set.[/red]")
        sys.exit(1)

    return url.rstrip("/"), api_key, verify_ssl, timeout


@click.command()
@click.argument("csv_file", required=False, type=click.Path(dir_okay=False))
@click.option("--skip-invalid", is_flag=True, help="Skip invalid rows instead of failing")
@click.option("--continue-on-error", is_flag=True, default=True, help="Continue uploading if individual events fail")
@click.option("--dry-run", is_flag=True, help="Validate CSV without uploading")
@click.option("--template", is_flag=True, help="Show CSV field descriptions and exit")
@click.option("--env-file", type=click.Path(exists=True), help="Path to .env file")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(
    csv_file: Optional[str],
    skip_invalid: bool,
    continue_on_error: bool,
    dry_run: bool,
    template: bool,
    env_file: Optional[str],
    debug: bool,
):
    """Bulk upload DDoS events to MISP from a CSV file.

    \b
    CSV_FILE  Path to the CSV file containing DDoS events.

    \b
    Examples:
        python main.py events.csv
        python main.py events.csv --dry-run
        python main.py events.csv --skip-invalid
        python main.py --template
    """
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    import bulk_cli

    if template:
        bulk_cli._show_template_info()
        sys.exit(0)

    if not csv_file:
        console.print("[red]ERROR: CSV_FILE is required. Use --template to see field descriptions.[/red]")
        sys.exit(1)

    if not Path(csv_file).exists():
        console.print(f"[red]ERROR: File not found: {csv_file}[/red]")
        sys.exit(1)

    url, api_key, verify_ssl, timeout = load_config(env_file)

    try:
        misp_client = MISPClient(url=url, api_key=api_key, verify_ssl=verify_ssl, timeout=timeout)
    except MISPConnectionError as e:
        console.print(f"[red]Connection failed: {e}[/red]")
        console.print("  Check MISP_URL, MISP_API_KEY, and network settings.")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Initialization error: {e}[/red]")
        sys.exit(1)

    result = bulk_cli.run(
        misp_client=misp_client,
        filepath=csv_file,
        skip_invalid=skip_invalid,
        continue_on_error=continue_on_error,
        dry_run=dry_run,
    )

    if not result:
        sys.exit(1)
    if isinstance(result, dict) and result.get("failed"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
