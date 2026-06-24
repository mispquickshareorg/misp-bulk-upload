"""MISP client for creating DDoS events."""

import logging
import time
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple, Callable

import requests
from urllib3.util.retry import Retry
from pymisp import ExpandedPyMISP, MISPEvent, MISPObject, MISPAttribute
from pymisp.exceptions import PyMISPError

logger = logging.getLogger(__name__)


class MISPClientError(Exception):
    pass


class MISPConnectionError(MISPClientError):
    pass


class MISPValidationError(MISPClientError):
    pass


def _retry(max_attempts=3, backoff=2.0, exceptions=(requests.RequestException, PyMISPError)):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt >= max_attempts:
                        raise MISPConnectionError(f"Failed after {max_attempts} attempts: {e}") from e
                    wait = backoff ** attempt
                    logger.warning(f"{func.__name__} attempt {attempt}/{max_attempts} failed, retrying in {wait}s")
                    time.sleep(wait)
        return wrapper
    return decorator


class MISPClient:
    LOCAL_WORKFLOW_TAG = 'workflow:state="draft"'
    MITRE_GALAXY_CLUSTER = 'misp-galaxy:mitre-attack-pattern="Network Denial of Service - T1498"'
    VALID_TLP_LEVELS = ["clear", "green", "amber", "red"]

    _TEMPLATE_META = {
        "ja3":      {"uuid": "09b45449-5d6e-492c-a68a-cb2e188cbfac", "version": 4},
        "ja3s":     {"uuid": "7f377f66-d128-4b97-897f-592d06ba2ff7", "version": 5},
        "ja4-plus": {"uuid": "2c15c75e-e7db-4b62-8d17-633e7571818f", "version": 2},
    }

    TLS_OBJECT_FINGERPRINTS = {
        "ja3":    {"object_name": "ja3",      "attribute_name": "ja3-fingerprint-md5",  "attribute_type": "ja3-fingerprint-md5"},
        "ja3s":   {"object_name": "ja3s",     "attribute_name": "ja3s-fingerprint-md5", "attribute_type": "ja3-fingerprint-md5"},
        "ja4":    {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4"},
        "ja4s":   {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4S"},
        "ja4h":   {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4H"},
        "ja4x":   {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4X"},
        "ja4t":   {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4T"},
        "ja4ts":  {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4TS"},
        "ja4ssh": {"object_name": "ja4-plus", "attribute_name": "ja4-fingerprint", "attribute_type": "text", "ja4_type": "JA4SSH"},
    }

    TLS_ATTRIBUTE_FINGERPRINTS = {
        "jarm":        "jarm-fingerprint",
        "hassh":       "hassh-md5",
        "hasshserver": "hasshserver-md5",
    }

    TLS_FINGERPRINT_TYPES = {
        **{k: v["attribute_name"] for k, v in TLS_OBJECT_FINGERPRINTS.items()},
        **TLS_ATTRIBUTE_FINGERPRINTS,
    }

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True, timeout: int = 30):
        if not url or not url.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        if not api_key:
            raise ValueError("API key must not be empty")

        self.url = url.rstrip("/")
        self._api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            self.client = ExpandedPyMISP(
                url=self.url, key=self._api_key, ssl=self.verify_ssl, timeout=self.timeout
            )
        except Exception as e:
            raise MISPConnectionError(f"Failed to initialize MISP client: {e}") from e

        self._test_connection()

    @_retry(max_attempts=3)
    def _test_connection(self):
        try:
            self.client.misp_instance_version
        except Exception as e:
            raise MISPConnectionError(f"Failed to connect to MISP: {e}") from e

    def _validate_ip_address(self, ip: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _validate_port(self, port: int) -> bool:
        return isinstance(port, int) and 1 <= port <= 65535

    def _validate_tls_fingerprint(self, fp_type: str, fp_value: str) -> bool:
        import re
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

    @_retry(max_attempts=3)
    def create_ddos_event(
        self,
        event_name: str,
        event_date: str,
        attacker_ips: List[str],
        destination_ips: Optional[List[str]] = None,
        destination_ports: Optional[List[int]] = None,
        annotation_text: str = "",
        tlp: str = "green",
        tls_fingerprints: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        if not event_name or not event_name.strip():
            raise MISPValidationError("Event name must not be empty")
        if not event_date or not event_date.strip():
            raise MISPValidationError("Event date must not be empty")
        if not attacker_ips:
            raise MISPValidationError("At least one attacker IP is required")

        for ip in attacker_ips:
            if not self._validate_ip_address(ip):
                raise MISPValidationError(f"Invalid attacker IP: {ip}")

        if destination_ips:
            for ip in destination_ips:
                if not self._validate_ip_address(ip):
                    raise MISPValidationError(f"Invalid destination IP: {ip}")

        tlp_lower = tlp.lower()
        if tlp_lower not in self.VALID_TLP_LEVELS:
            raise MISPValidationError(f"Invalid TLP level: {tlp}. Must be one of {self.VALID_TLP_LEVELS}")

        if tls_fingerprints:
            for fp_type, fp_values in tls_fingerprints.items():
                if fp_type.lower() not in self.TLS_FINGERPRINT_TYPES:
                    raise MISPValidationError(f"Unknown TLS fingerprint type: {fp_type}")
                for fp_value in fp_values:
                    if not self._validate_tls_fingerprint(fp_type, fp_value):
                        raise MISPValidationError(f"Invalid {fp_type} fingerprint: {fp_value}")

        try:
            event = MISPEvent()
            event.info = event_name
            event.date = event_date
            event.add_tag(f"tlp:{tlp_lower}")
            event.add_tag(self.MITRE_GALAXY_CLUSTER)
            event.add_tag(self.LOCAL_WORKFLOW_TAG)

            if annotation_text:
                ann = MISPObject("annotation")
                ann.add_attribute("text", value=annotation_text)
                event.add_object(ann)

            ip_port_obj = MISPObject("ip-port")
            for ip in attacker_ips:
                ip_port_obj.add_attribute("ip-src", value=ip)
            if destination_ips:
                for idx, dest_ip in enumerate(destination_ips):
                    ip_port_obj.add_attribute("ip-dst", value=dest_ip)
                    if destination_ports and idx < len(destination_ports):
                        port = destination_ports[idx]
                        if self._validate_port(port):
                            ip_port_obj.add_attribute("dst-port", value=str(port))
            ip_port_obj.comment = "Attacker IPs" + (" and Destination IPs/Ports" if destination_ips else "")
            event.add_object(ip_port_obj)

            if tls_fingerprints:
                for fp_type, fp_values in tls_fingerprints.items():
                    fp_type_lower = fp_type.lower()
                    if fp_type_lower in self.TLS_OBJECT_FINGERPRINTS:
                        obj_info = self.TLS_OBJECT_FINGERPRINTS[fp_type_lower]
                        for fp_value in fp_values:
                            fp_obj = MISPObject(obj_info["object_name"], strict=False)
                            tmeta = self._TEMPLATE_META.get(obj_info["object_name"])
                            if tmeta:
                                fp_obj.template_uuid = tmeta["uuid"]
                                fp_obj.template_version = tmeta["version"]
                            fp_obj.add_attribute(
                                obj_info["attribute_name"],
                                value=fp_value.strip(),
                                type=obj_info["attribute_type"],
                                to_ids=True,
                            )
                            if "ja4_type" in obj_info:
                                fp_obj.add_attribute("ja4-type", value=obj_info["ja4_type"], type="text", disable_correlation=True)
                            fp_obj.comment = f"{fp_type.upper()} TLS fingerprint"
                            event.add_object(fp_obj)
                    elif fp_type_lower in self.TLS_ATTRIBUTE_FINGERPRINTS:
                        misp_attr_type = self.TLS_ATTRIBUTE_FINGERPRINTS[fp_type_lower]
                        for fp_value in fp_values:
                            attr = MISPAttribute()
                            attr.type = misp_attr_type
                            attr.value = fp_value.strip()
                            attr.comment = f"{fp_type.upper()} TLS fingerprint"
                            attr.to_ids = True
                            event.add_attribute(**attr.to_dict())

            response = self.client.add_event(event, pythonify=True)

            return {
                "success": True,
                "event_id": response.id,
                "event_uuid": response.uuid,
                "event_name": event_name,
                "url": f"{self.url}/events/view/{response.id}",
            }

        except PyMISPError as e:
            raise MISPConnectionError(f"Failed to create event: {e}") from e
        except MISPValidationError:
            raise
        except Exception as e:
            raise MISPClientError(f"Unexpected error: {e}") from e
