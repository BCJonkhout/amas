"""Structured access to the enterprise security datasets."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class DatasetConfig:
    dataset_id: str
    file_name: str
    root_key: Optional[str]
    description: str


DATASET_CATALOGUE: List[DatasetConfig] = [
    DatasetConfig("cmdb", "cmdb.json", "cmdb_assets", "Configuration Management Database assets"),
    DatasetConfig("iam", "iam_hr_database.json", "iam_users", "Identity and access management records"),
    DatasetConfig("network_vlans", "network-architecture_vlan_documentation.json", "network_vlans", "VLAN and network zone documentation"),
    DatasetConfig("service_policy", "approved_port_service_usage_policy.json", "service_policy", "Port and service usage policies"),
    DatasetConfig("threat_intel", "threat_intelligence.json", "threat_intelligence_indicators", "Threat intelligence indicators of compromise"),
    DatasetConfig("ueba", "user_entity_behaviour_analytics.json", "ueba_profiles", "User and entity behaviour analytics baselines"),
    DatasetConfig("edr_events", "endpoint_security_logs.json", "edr_events", "Endpoint detection and response telemetry"),
    DatasetConfig("dns_proxy", "web_proxy_dns_logs.json", None, "DNS and web proxy telemetry"),
    DatasetConfig("vuln_scans", "vulnerability_scan_database.json", "vulnerability_findings", "Vulnerability scan results"),
    DatasetConfig("playbooks", "incident_response_playbooks.json", "incident_response_playbooks", "Incident response playbooks"),
]


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _candidate_dataset_dirs(data_directory: Optional[Path]) -> List[Path]:
    candidates: List[Path] = []
    if data_directory:
        base = Path(data_directory).expanduser()
        candidates.extend([base, base / "organisation-documents"])

    env_override = os.environ.get("AMAS_DATA_DIR")
    if env_override:
        env_path = Path(env_override).expanduser()
        candidates.extend([env_path, env_path / "organisation-documents"])

    project_data = PROJECT_ROOT / "data"
    candidates.extend([project_data, project_data / "organisation-documents"])

    unique: List[Path] = []
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


def _resolve_dataset_dir(data_directory: Optional[Path]) -> Path:
    attempts: List[Path] = []
    for candidate in _candidate_dataset_dirs(data_directory):
        attempts.append(candidate)
        if not candidate.is_dir():
            continue
        if all((candidate / config.file_name).is_file() for config in DATASET_CATALOGUE):
            return candidate
        nested = candidate / "organisation-documents"
        if nested.is_dir() and all((nested / config.file_name).is_file() for config in DATASET_CATALOGUE):
            return nested.resolve()
    attempted = ", ".join(str(path) for path in attempts)
    raise FileNotFoundError(f"Dataset directory not found. Checked: {attempted}")


class SecurityDataRepository:
    """In-memory cache and query layer for the JSON datasets."""

    def __init__(self, data_directory: Optional[Path] = None) -> None:
        base_dir = _resolve_dataset_dir(data_directory)
        self._data_directory = base_dir
        self._datasets: Dict[str, Any] = {}
        self._load_all()

    def _load_all(self) -> None:
        for config in DATASET_CATALOGUE:
            path = self._data_directory / config.file_name
            if not path.is_file():
                raise FileNotFoundError(f"Dataset missing: {path}")

            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)

            if config.root_key is None:
                self._datasets[config.dataset_id] = payload
            else:
                self._datasets[config.dataset_id] = payload.get(config.root_key, [])

    def dataset_ids(self) -> Iterable[str]:
        return self._datasets.keys()

    def get_all(self, dataset_id: str) -> Any:
        return self._datasets[dataset_id]

    def query(
        self,
        dataset_id: str,
        query: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Return filtered data for the requested dataset."""

        dataset = self._datasets[dataset_id]
        if dataset_id == "dns_proxy":
            records = self._normalise_dns_proxy_records(dataset)
        else:
            records = list(dataset)

        filtered = [
            record
            for record in records
            if self._matches_filters(record, filters) and self._matches_query(record, query)
        ]

        if dataset_id == "dns_proxy":
            return filtered
        return filtered

    @staticmethod
    def _normalise_dns_proxy_records(raw_payload: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Flatten DNS and web proxy logs into a single iterable with explicit type tagging."""

        flattened: List[Dict[str, Any]] = []
        for log_type, entries in raw_payload.items():
            for entry in entries:
                tagged = dict(entry)
                tagged["log_type"] = log_type
                flattened.append(tagged)
        return flattened

    @staticmethod
    def _matches_filters(record: Dict[str, Any], filters: Optional[Dict[str, Any]]) -> bool:
        if not filters:
            return True

        for key, expected in filters.items():
            value = SecurityDataRepository._dig(record, key)
            if isinstance(expected, (list, tuple, set)):
                if isinstance(value, list):
                    if not any(SecurityDataRepository._value_equals(v, expected_item) for v in value for expected_item in expected):
                        return False
                else:
                    if value not in expected:
                        return False
            else:
                if isinstance(value, list):
                    if not any(SecurityDataRepository._value_equals(item, expected) for item in value):
                        return False
                elif not SecurityDataRepository._value_equals(value, expected):
                    return False
        return True

    @staticmethod
    def _matches_query(record: Dict[str, Any], query: Optional[str]) -> bool:
        if not query:
            return True

        lowered = query.lower()
        return SecurityDataRepository._contains_text(record, lowered)

    @staticmethod
    def _contains_text(value: Any, needle: str) -> bool:
        if isinstance(value, dict):
            return any(SecurityDataRepository._contains_text(v, needle) for v in value.values())
        if isinstance(value, list):
            return any(SecurityDataRepository._contains_text(item, needle) for item in value)
        if value is None:
            return False
        return needle in str(value).lower()

    @staticmethod
    def _dig(record: Dict[str, Any], dotted_path: str) -> Any:
        current: Any = record
        for part in dotted_path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    @staticmethod
    def _value_equals(actual: Any, expected: Any) -> bool:
        if isinstance(actual, str) and isinstance(expected, str):
            return actual.lower() == expected.lower()
        return actual == expected
