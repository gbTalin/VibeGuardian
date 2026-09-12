from dataclasses import dataclass
from typing import Protocol

import httpx

from cg_threat_intel.services.requirements import PythonDependency

OSV_API_URL = "https://api.osv.dev/v1"


@dataclass(frozen=True)
class OsvVulnerability:
    id: str
    summary: str
    aliases: list[str]
    severity: str | None
    references: list[str]


class VulnerabilityIntelligenceClient(Protocol):
    def query_python_dependencies(self, dependencies: list[PythonDependency]) -> dict[str, list[OsvVulnerability]]:
        """Return vulnerabilities keyed by normalized dependency name."""


class OsvClient:
    """Minimal OSV client using batch matching followed by record retrieval."""

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client or httpx.Client(timeout=10.0, follow_redirects=False)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def query_python_dependencies(self, dependencies: list[PythonDependency]) -> dict[str, list[OsvVulnerability]]:
        payload = {
            "queries": [
                {
                    "package": {"name": dependency.normalized_name, "ecosystem": "PyPI"},
                    "version": dependency.version,
                }
                for dependency in dependencies
            ]
        }
        response = self._client.post(f"{OSV_API_URL}/querybatch", json=payload)
        response.raise_for_status()
        results = response.json().get("results", [])
        if len(results) != len(dependencies):
            raise RuntimeError("OSV returned a response that could not be matched to submitted dependencies.")

        matched: dict[str, list[OsvVulnerability]] = {}
        for dependency, result in zip(dependencies, results, strict=True):
            records = []
            for entry in result.get("vulns", []):
                vulnerability_id = entry.get("id")
                if vulnerability_id:
                    records.append(self._fetch_vulnerability(vulnerability_id))
            matched[dependency.normalized_name] = records
        return matched

    def _fetch_vulnerability(self, vulnerability_id: str) -> OsvVulnerability:
        response = self._client.get(f"{OSV_API_URL}/vulns/{vulnerability_id}")
        response.raise_for_status()
        record = response.json()
        references = [item["url"] for item in record.get("references", []) if item.get("url")]
        database_specific = record.get("database_specific", {})
        severity = database_specific.get("severity")
        if severity is None:
            severity = _affected_severity(record)
        return OsvVulnerability(
            id=record["id"],
            summary=record.get("summary") or "No summary supplied by OSV.",
            aliases=record.get("aliases", []),
            severity=severity,
            references=references,
        )


def _affected_severity(record: dict) -> str | None:
    for affected in record.get("affected", []):
        severity = affected.get("ecosystem_specific", {}).get("severity")
        if severity:
            return severity
    return None

