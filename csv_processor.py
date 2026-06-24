"""CSV validator and processor for bulk MISP DDoS event uploads."""

import csv
import logging
import re
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CSVValidationError(Exception):
    pass


class DDoSEventValidator:
    REQUIRED_FIELDS = ["date", "event_name", "attacker_ips", "annotation_text"]

    OPTIONAL_FIELDS = [
        "tlp", "destination_ips", "destination_ports",
        "ja3", "ja3s", "ja4", "ja4s", "ja4h", "ja4x",
        "ja4t", "ja4ts", "ja4ssh", "jarm", "hassh", "hasshserver",
    ]

    VALID_TLP_LEVELS = ["clear", "green", "amber", "red"]

    TLS_FINGERPRINT_COLUMNS = [
        "ja3", "ja3s", "ja4", "ja4s", "ja4h", "ja4x",
        "ja4t", "ja4ts", "ja4ssh", "jarm", "hassh", "hasshserver",
    ]

    MAX_EVENT_NAME_LENGTH = 255
    MAX_DESCRIPTION_LENGTH = 5000
    MAX_IPS = 1000

    def _validate_ip(self, ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(ip.strip())
            return True
        except ValueError:
            return False

    def _validate_port(self, port: str) -> bool:
        try:
            return 1 <= int(port) <= 65535
        except (ValueError, TypeError):
            return False

    def _validate_date(self, date_str: str) -> bool:
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S"):
            try:
                datetime.strptime(date_str.strip(), fmt)
                return True
            except ValueError:
                continue
        return False

    def _validate_tls_fingerprint(self, fp_type: str, fp_value: str) -> bool:
        if not fp_value or not isinstance(fp_value, str):
            return False
        fp_value = fp_value.strip()
        fp_type = fp_type.lower()
        if fp_type in ("ja3", "ja3s"):
            return bool(re.match(r'^[a-fA-F0-9]{32}$', fp_value))
        if fp_type.startswith("ja4"):
            return bool(re.match(r'^[a-zA-Z0-9_]{10,50}$', fp_value))
        if fp_type == "jarm":
            return bool(re.match(r'^[a-fA-F0-9]{62}$', fp_value))
        if fp_type in ("hassh", "hasshserver"):
            return bool(re.match(r'^[a-fA-F0-9]{32}$', fp_value))
        return bool(re.match(r'^[a-zA-Z0-9_\-:]+$', fp_value))

    def validate_row(self, row: Dict[str, str], row_number: int) -> Dict[str, Any]:
        errors = []

        for field in self.REQUIRED_FIELDS:
            if field not in row or not row[field].strip():
                errors.append(f"Row {row_number}: Missing required field '{field}'")
        if errors:
            raise CSVValidationError("\n".join(errors))

        event_name = row["event_name"].strip()
        if len(event_name) > self.MAX_EVENT_NAME_LENGTH:
            errors.append(f"Row {row_number}: Event name exceeds {self.MAX_EVENT_NAME_LENGTH} characters")

        annotation_text = row["annotation_text"].strip()
        if len(annotation_text) > self.MAX_DESCRIPTION_LENGTH:
            errors.append(f"Row {row_number}: Annotation text exceeds {self.MAX_DESCRIPTION_LENGTH} characters")

        date_str = row["date"].strip()
        if not self._validate_date(date_str):
            errors.append(f"Row {row_number}: Invalid date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")

        attacker_ips = [ip.strip() for ip in row["attacker_ips"].split(";") if ip.strip()]
        if not attacker_ips:
            errors.append(f"Row {row_number}: No attacker IPs provided")
        elif len(attacker_ips) > self.MAX_IPS:
            errors.append(f"Row {row_number}: Too many attacker IPs (max {self.MAX_IPS})")
        for ip in attacker_ips:
            if not self._validate_ip(ip):
                errors.append(f"Row {row_number}: Invalid attacker IP '{ip}'")

        destination_ips = []
        if row.get("destination_ips", "").strip():
            destination_ips = [ip.strip() for ip in row["destination_ips"].split(";") if ip.strip()]
            if len(destination_ips) > self.MAX_IPS:
                errors.append(f"Row {row_number}: Too many destination IPs (max {self.MAX_IPS})")
            for ip in destination_ips:
                if not self._validate_ip(ip):
                    errors.append(f"Row {row_number}: Invalid destination IP '{ip}'")

        destination_ports = []
        if row.get("destination_ports", "").strip():
            for p in row["destination_ports"].split(";"):
                p = p.strip()
                if p:
                    if not self._validate_port(p):
                        errors.append(f"Row {row_number}: Invalid destination port '{p}'")
                    else:
                        destination_ports.append(int(p))

        tlp = row.get("tlp", "green").strip().lower()
        if tlp and tlp not in self.VALID_TLP_LEVELS:
            errors.append(f"Row {row_number}: Invalid TLP '{tlp}'. Must be one of {self.VALID_TLP_LEVELS}")

        if errors:
            raise CSVValidationError("\n".join(errors))

        tls_fingerprints = {}
        for fp_col in self.TLS_FINGERPRINT_COLUMNS:
            if row.get(fp_col, "").strip():
                fp_values = [v.strip() for v in row[fp_col].split(";") if v.strip()]
                valid_fps = []
                for fp_value in fp_values:
                    if self._validate_tls_fingerprint(fp_col, fp_value):
                        valid_fps.append(fp_value)
                    else:
                        errors.append(f"Row {row_number}: Invalid {fp_col.upper()} fingerprint: '{fp_value}'")
                if valid_fps:
                    tls_fingerprints[fp_col] = valid_fps

        if errors:
            raise CSVValidationError("\n".join(errors))

        return {
            "event_name": event_name,
            "event_date": date_str,
            "attacker_ips": attacker_ips,
            "destination_ips": destination_ips if destination_ips else None,
            "destination_ports": destination_ports if destination_ports else None,
            "annotation_text": annotation_text,
            "tlp": tlp if tlp else "green",
            "tls_fingerprints": tls_fingerprints if tls_fingerprints else None,
        }


class CSVProcessor:
    MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

    def __init__(self):
        self.validator = DDoSEventValidator()

    def _validate_file(self, filepath: str) -> Path:
        path = Path(filepath).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {path}")
        if path.suffix.lower() != ".csv":
            raise ValueError(f"Not a CSV file: {path}")
        size = path.stat().st_size
        if size > self.MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File too large: {size / 1024 / 1024:.1f} MB (max 10 MB)")
        if size == 0:
            raise ValueError(f"File is empty: {path}")
        return path

    def process_csv(self, filepath: str, skip_invalid: bool = False) -> Dict[str, Any]:
        path = self._validate_file(filepath)
        valid_events = []
        invalid_rows: List[Tuple[int, str]] = []
        total_rows = 0

        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                lines = [line for line in f if line.strip() and not line.strip().startswith("#")]

            reader = csv.DictReader(StringIO("".join(lines)))

            if not reader.fieldnames:
                raise CSVValidationError("CSV file has no headers")

            missing = set(self.validator.REQUIRED_FIELDS) - set(reader.fieldnames)
            if missing:
                raise CSVValidationError(f"CSV missing required columns: {missing}")

            for idx, row in enumerate(reader, start=2):
                total_rows += 1
                try:
                    event_data = self.validator.validate_row(row, idx)
                    valid_events.append(event_data)
                except CSVValidationError as e:
                    logger.warning(f"Invalid row {idx}: {e}")
                    invalid_rows.append((idx, str(e)))
                    if not skip_invalid:
                        raise

        except UnicodeDecodeError as e:
            raise CSVValidationError(f"File encoding error (must be UTF-8): {e}") from e
        except csv.Error as e:
            raise CSVValidationError(f"CSV parsing error: {e}") from e

        return {"valid_events": valid_events, "invalid_rows": invalid_rows, "total_rows": total_rows}
