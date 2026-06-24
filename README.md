# misp-bulk-upload

A CLI tool for bulk-creating DDoS events in [MISP](https://www.misp-project.org/) from a CSV file, following the Streamlined MISP DDoS Playbook.

It validates every row up front, then creates one structured MISP event per row with progress tracking and a detailed success/failure report.

## What it creates

For each CSV row, an event is created with:

- **TLP tag** (`clear`, `green`, `amber`, `red`; default `green`)
- **MITRE ATT&CK T1498** (Network Denial of Service) galaxy cluster
- **Workflow state** `draft`
- An **`ip-port` object** containing attacker (source) IPs, and optional destination IPs/ports
- An **`annotation` object** with the row's description
- Optional **TLS fingerprints** (JA3/JA3S/JA4 family as MISP objects; JARM/HASSH as attributes)

## Why it's minimal

- **No auto-update, no subprocess calls** - the tool never shells out or contacts anything other than your configured MISP URL.
- Single, focused command.
- Path/size validation and per-row validation are isolated in [csv_processor.py](csv_processor.py) for easy auditing.

## Requirements

- Python 3.8+
- Dependencies in [requirements.txt](requirements.txt) (`pymisp`, `click`, `rich`, `python-dotenv`)

## Installation

```bash
git clone https://github.com/mispquickshareorg/misp-bulk-upload.git
cd misp-bulk-upload
pip install -r requirements.txt
```

## Configuration

Copy the example environment file and fill in your MISP details:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISP_URL` | Yes | - | Base URL of your MISP instance (`https://...`) |
| `MISP_API_KEY` | Yes | - | Your MISP API authentication key |
| `MISP_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certificates |
| `MISP_TIMEOUT` | No | `30` | Request timeout in seconds |

> **Note:** `.env` is git-ignored. Never commit real credentials.

## CSV format

See [templates/ddos_event_template.csv](templates/ddos_event_template.csv) for the full template, or run `python main.py --template` for field descriptions.

**Required columns:** `date`, `event_name`, `attacker_ips`, `annotation_text`
**Optional columns:** `tlp`, `destination_ips`, `destination_ports`, and TLS fingerprint columns (`ja3`, `ja3s`, `ja4`, `ja4s`, `ja4h`, `ja4x`, `ja4t`, `ja4ts`, `ja4ssh`, `jarm`, `hassh`, `hasshserver`).

- Use a semicolon (`;`) to separate multiple values within a field.
- Lines starting with `#` are treated as comments and ignored.
- Date format: `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`.

## Usage

```bash
# Validate and upload events from a CSV
python main.py events.csv

# Validate only - do not upload
python main.py events.csv --dry-run

# Skip invalid rows instead of failing
python main.py events.csv --skip-invalid

# Show CSV field descriptions and exit
python main.py --template

# Use a specific env file
python main.py events.csv --env-file /path/to/.env
```

The tool prints a validation summary, an upload progress bar, and a final report of created and failed events. It exits `0` only if all events upload successfully.

## Security notes

- Input files are limited to 10 MB and validated (path, extension, size) before parsing to prevent abuse.
- All row values (IPs, dates, ports, fingerprints) are validated before submission.
- The API key is read from the environment only and is never logged.
- The only network destination is the `MISP_URL` you configure.

## License

MIT
