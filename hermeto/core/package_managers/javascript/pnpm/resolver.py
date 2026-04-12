import json
from collections import UserDict, deque
from collections.abc import Generator
from itertools import chain
from pathlib import Path
from typing import Any

import yaml
from packageurl import PackageURL

from hermeto.core.config import get_config
from hermeto.core.constants import Mode
from hermeto.core.errors import NotAGitRepo
from hermeto.core.models.sbom import (
    PROXY_COMMENT,
    Component,
    ExternalReference,
    Patch,
    PatchDiff,
    Pedigree,
    PropertySet,
)
from hermeto.core.package_managers.general import get_vcs_qualifiers
from hermeto.core.package_managers.javascript.pnpm.project import PnpmLock, PnpmPackage
from hermeto.core.package_managers.npm import NPM_REGISTRY_URL
from hermeto.core.rooted_path import RootedPath

JSR_REGISTRY_URL = "https://registry.jsr.com"


class PackageJson(UserDict):
    """Class representing package.json files."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Initialize a PackageJson object."""
        self.path = path
        super().__init__(data)

    @classmethod
    def from_file(cls, path: Path) -> "PackageJson":
        """Create a PackageJson object from a package.json file."""
        with path.open() as f:
            data = json.load(f)
            return cls(path, data)

    @classmethod
    def from_dir(cls, path: Path) -> "PackageJson":
        """Create a PackageJson object from a directory containing a package.json file."""
        return cls.from_file(path.joinpath("package.json"))


def _resolve_dev_dependencies(lockfile: PnpmLock) -> set[str]:
    """Find all transitive development dependencies in the project."""
    snapshots = lockfile.snapshots
    queue = deque(lockfile.root_dev_dependencies)

    seen = set()
    while queue:
        current_id = queue.popleft()
        seen.add(current_id)

        transitive_deps: dict[str, str] = snapshots.get(current_id, {}).get("dependencies", {})
        for name, version in transitive_deps.items():
            snapshot_id = f"{name}@{version}"
            if snapshot_id not in seen:
                queue.append(snapshot_id)

    return seen


def _generate_sbom_components(
    project_dir: RootedPath, lockfile: PnpmLock, packages: list[PnpmPackage]
) -> list[Component]:
    """Generate SBOM components for the given packages."""
    config = get_config()
    try:
        vcs_qualifiers = get_vcs_qualifiers(project_dir.root)
    except NotAGitRepo:
        if config.mode == Mode.PERMISSIVE:
            vcs_qualifiers = None
        else:
            raise

    proxy_url = config.npm.proxy_url

    dev_dependencies = _resolve_dev_dependencies(lockfile)
    components = []
    for package in packages:
        if proxy_url is not None:
            external_references = [ExternalReference(url=str(proxy_url), comment=PROXY_COMMENT)]
        else:
            external_references = None

        purl = _generate_purl_for(package, vcs_qualifiers)
        properties = PropertySet(npm_development=package.id in dev_dependencies).to_properties()
        pedigree = _get_pedigree_for(package, vcs_qualifiers, lockfile)

        components.append(
            Component(
                name=package.name,
                version=package.version,
                purl=purl.to_string(),
                properties=properties,
                external_references=external_references,
                pedigree=pedigree,
            )
        )

    components.append(_get_main_component(project_dir, vcs_qualifiers))
    components.extend(_get_workspace_components(project_dir, vcs_qualifiers))
    return components


def _get_main_component(
    project_dir: RootedPath, vcs_qualifiers: dict[str, str] | None
) -> Component:
    """Create a component for the main package."""
    package_json = PackageJson.from_dir(project_dir.path)

    name = package_json.get("name")
    version = package_json.get("version")
    if name is None:
        raise ValueError(f"Missing 'name' field in the {package_json.path}")

    subpath = str(project_dir.subpath_from_root)

    purl = PackageURL(
        type="npm",
        name=name.lower(),
        version=version,
        qualifiers=vcs_qualifiers,
        subpath=subpath,
    )
    return Component(name=name, version=version, purl=purl.to_string())


def _get_workspace_paths(project_dir: RootedPath) -> list[Path]:
    """Resolve workspace paths from pnpm-workspace.yaml file."""
    pnpm_workspace_path = project_dir.path / "pnpm-workspace.yaml"
    if not pnpm_workspace_path.exists():
        return []

    with pnpm_workspace_path.open() as f:
        pnpm_workspace = yaml.safe_load(f)
        globs = pnpm_workspace.get("packages", [])

    def all_paths_matching(glob: str) -> Generator[Path, None, None]:
        return (path.resolve() for path in project_dir.path.glob(glob) if path.is_dir())

    return list(chain.from_iterable(map(all_paths_matching, globs)))


def _get_workspace_components(
    project_dir: RootedPath, vcs_qualifiers: dict[str, str] | None
) -> list[Component]:
    """Create components for the workspace packages."""
    components = []

    workspace_paths = _get_workspace_paths(project_dir)
    for workspace_path in workspace_paths:
        package_json = PackageJson.from_dir(workspace_path)
        name = package_json.get("name")
        version = package_json.get("version")
        if name is None:
            raise ValueError(f"Missing 'name' field in the {package_json.path}")

        subpath = str(workspace_path.relative_to(project_dir.path))

        purl = PackageURL(
            type="npm",
            name=name.lower(),
            version=version,
            qualifiers=vcs_qualifiers,
            subpath=subpath,
        )
        components.append(Component(name=name, version=version, purl=purl.to_string()))

    return components


def _generate_purl_for(package: PnpmPackage, vcs_qualifiers: dict[str, str] | None) -> PackageURL:
    """Generate a PURL for the given pnpm package."""
    qualifiers: dict[str, str] = {}
    subpath = None

    if package.url.startswith("file:"):
        subpath = package.url.removeprefix("file:")
        if vcs_qualifiers is not None:
            qualifiers.update(vcs_qualifiers)

    elif JSR_REGISTRY_URL in package.url:
        qualifiers["repository_url"] = JSR_REGISTRY_URL

    elif NPM_REGISTRY_URL not in package.url:
        qualifiers["download_url"] = package.url

    return PackageURL(
        type="npm",
        namespace=package.scope.lower(),
        name=package.name.lower(),
        version=package.version,
        qualifiers=qualifiers,
        subpath=subpath,
    )


def _get_pedigree_for(
    package: PnpmPackage, vcs_qualifiers: dict[str, str] | None, lockfile: PnpmLock
) -> Pedigree | None:
    """Generate a Pedigree for the given pnpm package."""
    if vcs_qualifiers is None:
        return None

    patches = lockfile.patched_dependencies

    if package.id in patches:
        url = vcs_qualifiers["vcs_url"] + "#" + patches[package.id]["path"]
        pedigree = Pedigree(patches=[Patch(diff=PatchDiff(url=url))])
    elif package.name in patches:
        url = vcs_qualifiers["vcs_url"] + "#" + patches[package.name]["path"]
        pedigree = Pedigree(patches=[Patch(diff=PatchDiff(url=url))])
    else:
        pedigree = None

    return pedigree
