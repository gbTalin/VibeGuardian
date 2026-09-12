import re
from dataclasses import dataclass

_IDENTIFIER_PATTERN = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|OSV-[A-Za-z0-9._-]+)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExaIntelligenceLead:
    candidate_identifiers: list[str]
    source_urls: list[str]


def extract_exa_intelligence_lead(run_data: dict) -> ExaIntelligenceLead:
    """Extract bounded identifiers and citations from an Exa completed-run payload."""

    output = run_data.get("output") if isinstance(run_data.get("output"), dict) else {}
    encoded_output = str(output)[:100_000]
    identifiers = sorted({item.upper() for item in _IDENTIFIER_PATTERN.findall(encoded_output)})
    urls: set[str] = set()
    for result in output.get("results", []):
        if isinstance(result, dict) and isinstance(result.get("url"), str):
            urls.add(result["url"])
    for grounding in output.get("grounding", []):
        if not isinstance(grounding, dict):
            continue
        for citation in grounding.get("citations", []):
            if isinstance(citation, dict) and isinstance(citation.get("url"), str):
                urls.add(citation["url"])
    return ExaIntelligenceLead(candidate_identifiers=identifiers, source_urls=sorted(urls))
