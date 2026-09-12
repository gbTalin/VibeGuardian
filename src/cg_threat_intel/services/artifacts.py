import json
import tomllib
from dataclasses import dataclass

from cg_threat_intel.services.requirements import (
    ManifestParseError,
    PythonDependency,
    parse_pinned_requirements,
)


@dataclass(frozen=True)
class DependencyArtifact:
    artifact_type: str
    dependencies: list[PythonDependency]


def parse_dependency_artifact(artifact_type: str, content: str) -> DependencyArtifact:
    parsers = {
        "requirements": _parse_requirements,
        "poetry_lock": _parse_poetry_lock,
        "pipfile_lock": _parse_pipfile_lock,
        "cyclonedx_json": _parse_cyclonedx,
        "spdx_json": _parse_spdx,
    }
    parser = parsers.get(artifact_type)
    if parser is None:
        raise ManifestParseError(f"Unsupported artifact type: {artifact_type}.")
    dependencies = parser(content)
    if not dependencies:
        raise ManifestParseError("The artifact did not contain exact Python package versions.")
    return DependencyArtifact(artifact_type=artifact_type, dependencies=_deduplicate(dependencies))


def _parse_requirements(content: str) -> list[PythonDependency]:
    return parse_pinned_requirements(content)


def _parse_poetry_lock(content: str) -> list[PythonDependency]:
    try:
        document = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        raise ManifestParseError("Invalid poetry.lock TOML.") from error
    dependencies = []
    for package in document.get("package", []):
        name, version = package.get("name"), package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            dependencies.append(PythonDependency(name=name, version=version))
    return dependencies


def _parse_pipfile_lock(content: str) -> list[PythonDependency]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise ManifestParseError("Invalid Pipfile.lock JSON.") from error
    dependencies = []
    for section in ("default", "develop"):
        for name, metadata in document.get(section, {}).items():
            if not isinstance(metadata, dict):
                continue
            version = metadata.get("version")
            if isinstance(version, str) and version.startswith("=="):
                dependencies.append(PythonDependency(name=name, version=version[2:]))
    return dependencies


def _parse_cyclonedx(content: str) -> list[PythonDependency]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise ManifestParseError("Invalid CycloneDX JSON.") from error
    dependencies = []
    for component in document.get("components", []):
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        name, version = component.get("name"), component.get("version")
        if isinstance(purl, str) and purl.startswith("pkg:pypi/") and isinstance(name, str) and isinstance(version, str):
            dependencies.append(PythonDependency(name=name, version=version))
    return dependencies


def _parse_spdx(content: str) -> list[PythonDependency]:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise ManifestParseError("Invalid SPDX JSON.") from error
    dependencies = []
    for package in document.get("packages", []):
        if not isinstance(package, dict):
            continue
        external_refs = package.get("externalRefs", [])
        is_pypi = any(
            isinstance(reference, dict)
            and reference.get("referenceType") == "purl"
            and isinstance(reference.get("referenceLocator"), str)
            and reference["referenceLocator"].startswith("pkg:pypi/")
            for reference in external_refs
        )
        name, version = package.get("name"), package.get("versionInfo")
        if is_pypi and isinstance(name, str) and isinstance(version, str) and version != "NOASSERTION":
            dependencies.append(PythonDependency(name=name, version=version))
    return dependencies


def _deduplicate(dependencies: list[PythonDependency]) -> list[PythonDependency]:
    unique = {dependency.normalized_name: dependency for dependency in dependencies}
    return list(unique.values())
