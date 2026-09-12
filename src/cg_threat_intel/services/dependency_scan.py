from dataclasses import dataclass

from cg_threat_intel.services.osv import OsvVulnerability, VulnerabilityIntelligenceClient
from cg_threat_intel.services.requirements import PythonDependency


@dataclass(frozen=True)
class DependencyVulnerabilityMatch:
    dependency: PythonDependency
    vulnerability: OsvVulnerability


def correlate_python_dependencies(
    dependencies: list[PythonDependency], client: VulnerabilityIntelligenceClient
) -> list[DependencyVulnerabilityMatch]:
    """Return exact package/version matches from the intelligence provider."""

    matches: list[DependencyVulnerabilityMatch] = []
    vulnerabilities_by_dependency = client.query_python_dependencies(dependencies)
    for dependency in dependencies:
        for vulnerability in vulnerabilities_by_dependency.get(dependency.normalized_name, []):
            matches.append(DependencyVulnerabilityMatch(dependency=dependency, vulnerability=vulnerability))
    return matches

