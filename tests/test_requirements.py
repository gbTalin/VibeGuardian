import pytest

from cg_threat_intel.services.dependency_scan import correlate_python_dependencies
from cg_threat_intel.services.osv import OsvVulnerability
from cg_threat_intel.services.requirements import ManifestParseError, parse_pinned_requirements


class StubIntelligenceClient:
    def query_python_dependencies(self, dependencies):
        return {
            "django": [
                OsvVulnerability(
                    id="GHSA-example",
                    summary="Example advisory",
                    aliases=["CVE-2026-0001"],
                    severity="HIGH",
                    references=["https://example.invalid/advisory"],
                )
            ]
        }


def test_parses_pinned_requirements_and_builds_purls() -> None:
    dependencies = parse_pinned_requirements("Django==4.2.0\nrequests==2.31.0\n")

    assert [dependency.normalized_name for dependency in dependencies] == ["django", "requests"]
    assert dependencies[0].purl == "pkg:pypi/django@4.2.0"


def test_rejects_unpinned_requirement() -> None:
    with pytest.raises(ManifestParseError, match="exact `package==version`"):
        parse_pinned_requirements("Django>=4.2\n")


def test_correlates_an_exact_dependency_version_with_intelligence() -> None:
    dependencies = parse_pinned_requirements("Django==4.2.0\nrequests==2.31.0\n")

    matches = correlate_python_dependencies(dependencies, StubIntelligenceClient())

    assert len(matches) == 1
    assert matches[0].dependency.name == "Django"
    assert matches[0].vulnerability.id == "GHSA-example"
