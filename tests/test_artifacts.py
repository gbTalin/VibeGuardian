import pytest

from cg_threat_intel.services.artifacts import parse_dependency_artifact
from cg_threat_intel.services.requirements import ManifestParseError


@pytest.mark.parametrize(
    ("artifact_type", "content"),
    [
        ("poetry_lock", '[[package]]\nname = "Django"\nversion = "4.2.0"\n'),
        ("pipfile_lock", '{"default":{"django":{"version":"==4.2.0"}}}'),
        (
            "cyclonedx_json",
            '{"components":[{"name":"Django","version":"4.2.0","purl":"pkg:pypi/django@4.2.0"}]}',
        ),
        (
            "spdx_json",
            '{"packages":[{"name":"Django","versionInfo":"4.2.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/django@4.2.0"}]}]}',
        ),
    ],
)
def test_parses_supported_python_artifacts(artifact_type: str, content: str) -> None:
    artifact = parse_dependency_artifact(artifact_type, content)

    assert artifact.dependencies[0].normalized_name == "django"
    assert artifact.dependencies[0].version == "4.2.0"


def test_ignores_non_pypi_sbom_components() -> None:
    with pytest.raises(ManifestParseError, match="exact Python package versions"):
        parse_dependency_artifact(
            "cyclonedx_json",
            '{"components":[{"name":"openssl","version":"3.0","purl":"pkg:deb/debian/openssl@3.0"}]}',
        )
