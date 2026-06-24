"""Bulk upload handler for processing CSV files with multiple DDoS events."""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from misp_client import MISPClient, MISPClientError, MISPConnectionError, MISPValidationError
from csv_processor import CSVProcessor, CSVValidationError

logger = logging.getLogger(__name__)
console = Console()


def _show_template_info():
    console.print("\n[bold cyan]CSV Template Field Reference[/bold cyan]\n")
    console.print("[bold]Required fields:[/bold]")
    console.print("  [cyan]date[/cyan]             - YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    console.print("  [cyan]event_name[/cyan]       - Event title (max 255 chars)")
    console.print("  [cyan]attacker_ips[/cyan]     - Attacker source IPs (semicolon-separated)")
    console.print("  [cyan]annotation_text[/cyan]  - Detailed description of the attack\n")
    console.print("[bold]Optional fields:[/bold]")
    console.print("  [cyan]tlp[/cyan]              - clear | green (default) | amber | red")
    console.print("  [cyan]destination_ips[/cyan]  - Target IPs (semicolon-separated)")
    console.print("  [cyan]destination_ports[/cyan]- Target ports (semicolon-separated)\n")
    console.print("[bold]TLS fingerprint fields (all optional, semicolon-separated):[/bold]")
    console.print("  [cyan]ja3[/cyan], [cyan]ja3s[/cyan]          - 32-char MD5 hash")
    console.print("  [cyan]ja4[/cyan], [cyan]ja4s[/cyan], [cyan]ja4h[/cyan], [cyan]ja4x[/cyan], [cyan]ja4t[/cyan], [cyan]ja4ts[/cyan], [cyan]ja4ssh[/cyan]  - JA4 variants")
    console.print("  [cyan]jarm[/cyan]             - 62-char hex")
    console.print("  [cyan]hassh[/cyan], [cyan]hasshserver[/cyan] - 32-char MD5 hash\n")
    console.print("[bold]Example row:[/bold]")
    console.print("[dim]2025-10-28,DDoS Botnet Attack,green,203.0.113.10;203.0.113.11,,,Large-scale DDoS from botnet[/dim]\n")
    template_path = Path("templates/ddos_event_template.csv")
    if template_path.exists():
        console.print(f"[green]Template file:[/green] {template_path.resolve()}")


def validate_csv(filepath: str, skip_invalid: bool = False) -> Dict[str, Any]:
    processor = CSVProcessor()
    console.print(f"\n[cyan]Validating {filepath}...[/cyan]\n")

    with console.status("[cyan]Reading and validating rows...[/cyan]"):
        result = processor.process_csv(filepath, skip_invalid=skip_invalid)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("Total Rows", str(result["total_rows"]))
    table.add_row("Valid Events", f"[green]{len(result['valid_events'])}[/green]")
    table.add_row("Invalid Rows", f"[red]{len(result['invalid_rows'])}[/red]")
    console.print(table)

    if result["invalid_rows"]:
        console.print("\n[bold yellow]Invalid rows:[/bold yellow]\n")
        err_table = Table(show_header=True, header_style="bold red")
        err_table.add_column("Row", style="red", justify="right")
        err_table.add_column("Error", style="yellow")
        for row_num, error in result["invalid_rows"][:10]:
            err_table.add_row(str(row_num), error)
        if len(result["invalid_rows"]) > 10:
            err_table.add_row("...", f"and {len(result['invalid_rows']) - 10} more")
        console.print(err_table)

    return result


def upload_events(misp_client: MISPClient, events: List[Dict[str, Any]], continue_on_error: bool = True) -> Dict[str, Any]:
    total = len(events)
    successful = []
    failed = []
    start = time.time()

    console.print(f"\n[cyan]Uploading {total} event(s) to MISP...[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Uploading...", total=total)

        for idx, event_data in enumerate(events, start=1):
            name = event_data.get("event_name", f"Event {idx}")
            progress.update(task, description=f"[cyan]Uploading: {name[:50]}")
            try:
                result = misp_client.create_ddos_event(**event_data)
                successful.append({"event_name": name, "event_id": result["event_id"], "event_uuid": result["event_uuid"], "url": result["url"]})
            except (MISPValidationError, MISPConnectionError, MISPClientError) as e:
                failed.append({"event_name": name, "error": str(e), "index": idx})
                if not continue_on_error:
                    progress.update(task, completed=total)
                    break
            except Exception as e:
                failed.append({"event_name": name, "error": f"Unexpected: {e}", "index": idx})
                if not continue_on_error:
                    progress.update(task, completed=total)
                    break
            finally:
                progress.advance(task)

    return {"total": total, "successful": successful, "failed": failed, "duration": time.time() - start}


def display_results(results: Dict[str, Any]) -> None:
    console.print("\n[bold]Upload Results[/bold]\n")

    summary = Table(show_header=True, header_style="bold cyan")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", justify="right")
    summary.add_row("Total", str(results["total"]))
    summary.add_row("Successful", f"[green]{len(results['successful'])}[/green]")
    summary.add_row("Failed", f"[red]{len(results['failed'])}[/red]")
    summary.add_row("Duration", f"{results['duration']:.2f}s")
    console.print(summary)

    if results["successful"]:
        console.print("\n[bold green]Created events:[/bold green]\n")
        t = Table(show_header=True, header_style="bold green")
        t.add_column("Event Name", style="green")
        t.add_column("ID", justify="right", style="cyan")
        t.add_column("UUID", style="dim")
        for ev in results["successful"][:20]:
            t.add_row(ev["event_name"][:50], str(ev["event_id"]), ev["event_uuid"][:8] + "...")
        if len(results["successful"]) > 20:
            t.add_row(f"... and {len(results['successful']) - 20} more", "", "")
        console.print(t)

    if results["failed"]:
        console.print("\n[bold red]Failed events:[/bold red]\n")
        t = Table(show_header=True, header_style="bold red")
        t.add_column("Event Name", style="red")
        t.add_column("Error", style="yellow")
        for ev in results["failed"][:20]:
            t.add_row(ev["event_name"][:50], ev["error"][:100])
        if len(results["failed"]) > 20:
            t.add_row(f"... and {len(results['failed']) - 20} more", "")
        console.print(t)


def run(
    misp_client: MISPClient,
    filepath: str,
    skip_invalid: bool = False,
    continue_on_error: bool = True,
    dry_run: bool = False,
) -> Optional[Dict[str, Any]]:
    try:
        result = validate_csv(filepath, skip_invalid=skip_invalid)

        if not result["valid_events"]:
            console.print("\n[bold red]No valid events found in CSV[/bold red]")
            return None

        if result["invalid_rows"] and not skip_invalid:
            console.print("\n[yellow]CSV contains invalid rows. Use --skip-invalid to skip them.[/yellow]")
            return None

        if dry_run:
            console.print(f"\n[bold green]Dry run complete. {len(result['valid_events'])} events ready for upload.[/bold green]")
            return result

        upload_results = upload_events(misp_client, result["valid_events"], continue_on_error=continue_on_error)
        display_results(upload_results)

        if not upload_results["failed"]:
            console.print(f"\n[bold green]All {len(upload_results['successful'])} events uploaded successfully![/bold green]")
        elif upload_results["successful"]:
            console.print(f"\n[bold yellow]{len(upload_results['successful'])} uploaded, {len(upload_results['failed'])} failed.[/bold yellow]")
        else:
            console.print("\n[bold red]All events failed to upload.[/bold red]")

        return upload_results

    except FileNotFoundError as e:
        console.print(f"[red]File not found: {e}[/red]")
        return None
    except CSVValidationError as e:
        console.print(f"[red]CSV error: {e}[/red]")
        return None
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        logger.exception("Unexpected error in bulk upload")
        return None
