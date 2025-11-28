import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from hermeto.core.models.output import ProjectFile
from hermeto.core.rooted_path import RootedPath


@dataclass
class MavenComponentInfo:
    """Contains the data needed to generate a maven SBOM component."""

    name: str
    purl: str
    version: str
    scope: str
    included: bool
    missing_hash_in_file: Path | None


@dataclass
class ResolvedMavenPackage:
    """Contains all of the data for a resolved maven package."""

    package: MavenComponentInfo
    dependencies: list[MavenComponentInfo]
    projectfiles: list[ProjectFile]


class MavenDependency:
    """A Maven dependency from lockfile.json."""

    def __init__(self, dependency_dict: dict[str, Any]) -> None:
        """Initialize a MavenDependency."""
        self._dependency_dict = dependency_dict

    @property
    def group_id(self) -> str:
        """Get the group ID."""
        return self._dependency_dict["groupId"]

    @property
    def artifact_id(self) -> str:
        """Get the artifact ID."""
        return self._dependency_dict["artifactId"]

    @property
    def version(self) -> str:
        """Get the version."""
        return self._dependency_dict["version"]

    @property
    def name(self) -> str:
        """Get the full name (groupId:artifactId)."""
        return f"{self.group_id}:{self.artifact_id}"

    @property
    def scope(self) -> str:
        """Get the dependency scope."""
        return self._dependency_dict.get("scope", "compile")

    @property
    def checksum(self) -> str | None:
        """Get the checksum."""

        # Some checksums have additional information after the hash, so we need to split and take the first part
        raw_checksum = self._dependency_dict.get("checksum")
        if raw_checksum:
            return raw_checksum.split()[0]

        return None

    @property
    def checksum_algorithm(self) -> str | None:
        """Get the checksum algorithm."""
        return self._dependency_dict.get("checksumAlgorithm")

    @property
    def resolved_url(self) -> str | None:
        """Get the resolved URL."""
        return self._dependency_dict.get("resolved")

    @property
    def included(self) -> bool:
        """Return True if this dependency should be included."""
        return self._dependency_dict.get("included", True)

    @property
    def children(self) -> list[dict[str, Any]]:
        """Get the children dependencies."""
        return self._dependency_dict.get("children", [])

    def to_component_info(self) -> MavenComponentInfo:
        """Convert to MavenComponentInfo."""
        purl = PackageURL(
            type="maven",
            namespace=self.group_id,
            name=self.artifact_id,
            version=self.version,
        )

        return MavenComponentInfo(
            name=self.name,
            purl=str(purl),
            version=self.version,
            scope=self.scope,
            included=self.included,
            missing_hash_in_file=None if self.checksum else Path("lockfile.json"),
        )


class MavenLockfile:
    """A Maven lockfile.json file."""

    def __init__(self, lockfile_path: RootedPath, lockfile_data: dict[str, Any]) -> None:
        """Initialize a MavenLockfile."""
        self._lockfile_path = lockfile_path
        self._lockfile_data = lockfile_data
        self._dependencies = self._parse_dependencies()

    @property
    def lockfile_data(self) -> dict[str, Any]:
        """Get content of lockfile.json stored in Dictionary."""
        return self._lockfile_data

    @property
    def dependencies(self) -> list[MavenDependency]:
        """Get list of dependencies loaded from lockfile.json."""
        return self._dependencies

    @property
    def main_package_info(self) -> dict[str, Any]:
        """Get the main package information."""
        return {
            "groupId": self._lockfile_data["groupId"],
            "artifactId": self._lockfile_data["artifactId"],
            "version": self._lockfile_data["version"],
        }

    def _parse_dependencies(self) -> list[MavenDependency]:
        """Parse dependencies from lockfile data."""
        dependencies = []

        def parse_dependency_tree(dep_list: list[dict[str, Any]]) -> None:
            """Recursively parse dependency tree."""
            for dep_dict in dep_list:
                dep = MavenDependency(dep_dict)
                dependencies.append(dep)

                # Recursively parse children
                if dep.children:
                    parse_dependency_tree(dep.children)

        parse_dependency_tree(self._lockfile_data.get("dependencies", []))
        return dependencies

    @classmethod
    def from_file(cls, lockfile_path: RootedPath) -> "MavenLockfile":
        """Create a MavenLockfile from a lockfile.json file."""
        with lockfile_path.path.open("r") as f:
            lockfile_data = json.load(f)

        return cls(lockfile_path, lockfile_data)

    def get_main_package(self) -> MavenComponentInfo:
        """Get the main package as a MavenComponentInfo."""
        main_info = self.main_package_info
        purl = PackageURL(
            type="maven",
            namespace=main_info["groupId"],
            name=main_info["artifactId"],
            version=main_info["version"],
        )

        return MavenComponentInfo(
            name=f"{main_info['groupId']}:{main_info['artifactId']}",
            purl=str(purl),
            version=main_info["version"],
            scope="compile",
            included=True,
            missing_hash_in_file=None,
        )

    def get_sbom_components(self) -> list[MavenComponentInfo]:
        """Get all dependencies as MavenComponentInfo objects."""
        components = []
        for dependency in self.dependencies:
            if dependency.included:
                components.append(dependency.to_component_info())
        return components

    def get_dependencies_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of dependencies to download."""
        deps_to_download = {}

        for dependency in self.dependencies:
            if dependency.resolved_url:
                deps_to_download[dependency.resolved_url] = {
                    "checksum": dependency.checksum,
                    "checksum_algorithm": dependency.checksum_algorithm,
                    "group_id": dependency.group_id,
                    "artifact_id": dependency.artifact_id,
                    "version": dependency.version,
                }

        return deps_to_download

    def get_plugins_to_download(self) -> dict[str, dict[str, str | None]]:
        """Get dictionary of plugins and their dependencies to download."""
        plugins_to_download = {}

        def extract_dependency(dep_dict: dict[str, Any]) -> None:
            """Recursively extract a dependency and its children."""
            resolved_url = dep_dict.get("resolved")
            if resolved_url and resolved_url not in plugins_to_download:
                plugins_to_download[resolved_url] = {
                    "checksum": dep_dict.get("checksum"),
                    "checksum_algorithm": dep_dict.get("checksumAlgorithm"),
                    "group_id": dep_dict.get("groupId"),
                    "artifact_id": dep_dict.get("artifactId"),
                    "version": dep_dict.get("version"),
                }

            for child_dict in dep_dict.get("children", []):
                extract_dependency(child_dict)

        for plugin_dict in self._lockfile_data.get("mavenPlugins", []):
            resolved_url = plugin_dict.get("resolved")
            if resolved_url:
                plugins_to_download[resolved_url] = {
                    "checksum": plugin_dict.get("checksum"),
                    "checksum_algorithm": plugin_dict.get("checksumAlgorithm"),
                    "group_id": plugin_dict.get("groupId"),
                    "artifact_id": plugin_dict.get("artifactId"),
                    "version": plugin_dict.get("version"),
                }

            for dep_dict in plugin_dict.get("dependencies", []):
                extract_dependency(dep_dict)

        return plugins_to_download
