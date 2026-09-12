import re
from dataclasses import dataclass

_PINNED_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!~-]*)"
)


@dataclass(frozen=True)
class PythonDependency:
    name: str
    version: str

    @property
    def normalized_name(self) -> str:
        return self.name.lower().replace("_", "-").replace(".", "-")

    @property
    def purl(self) -> str:
        return f"pkg:pypi/{self.normalized_name}@{self.version}"


class ManifestParseError(ValueError):
    pass


def parse_pinned_requirements(content: str) -> list[PythonDependency]:
    """Parse only exact Python dependency pins from a requirements-style manifest.

    A production security decision needs an observed version. Unpinned, editable,
    URL, and included requirements are intentionally rejected for this MVP rather
    than guessed at.
    """

    dependencies: dict[str, PythonDependency] = {}
    unsupported: list[str] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", maxsplit=1)[0].strip()
        if not line:
            continue
        match = _PINNED_REQUIREMENT.match(line)
        if not match:
            unsupported.append(str(line_number))
            continue
        name, version = match.groups()
        dependency = PythonDependency(name=name, version=version)
        dependencies[dependency.normalized_name] = dependency

    if unsupported:
        joined = ", ".join(unsupported)
        raise ManifestParseError(
            "This MVP accepts exact `package==version` entries only. "
            f"Unsupported entries found on line(s): {joined}."
        )
    if not dependencies:
        raise ManifestParseError("No exact `package==version` dependency entries were found.")
    return list(dependencies.values())

