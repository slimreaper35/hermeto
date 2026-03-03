# SPDX-License-Identifier: GPL-3.0-only
import asyncio
import json
import logging
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

import aiohttp
import yaml
from packageurl import PackageURL

from hermeto.core.checksum import ChecksumInfo, must_match_any_checksum
from hermeto.core.config import get_config
from hermeto.core.errors import LockfileNotFound, PackageRejected, UnsupportedFeature
from hermeto.core.models.input import Request
from hermeto.core.models.output import ProjectFile, RequestOutput
from hermeto.core.models.property_semantics import PropertySet
from hermeto.core.models.sbom import (
    PROXY_COMMENT,
    PROXY_REF_TYPE,
    Annotation,
    Component,
    ExternalReference,
    create_backend_annotation,
)
from hermeto.core.package_managers.general import async_download_files
from hermeto.core.rooted_path import RootedPath
from hermeto.core.scm import get_repo_id

PACKAGE_JSON = "package.json"
PNPM_LOCK_YAML = "pnpm-lock.yaml"

NPM_REGISTRY_URL = "https://registry.npmjs.org"
JSR_REGISTRY_URL = "https://npm.jsr.io"

log = logging.getLogger(__name__)


def fetch_pnpm_source(request: Request) -> RequestOutput:
    """Process all pnpm source directories in the given request."""
    components: list[Component] = []
    project_files: list[ProjectFile] = []
    annotations: list[Annotation] = []

    deps_dir = request.output_dir.path.joinpath("deps", "pnpm")
    deps_dir.mkdir(parents=True, exist_ok=True)

    for package in request.pnpm_packages:
        project_dir = request.source_dir.join_within_root(package.path)
        _ensure_pnpm_files_exist(project_dir.path)

        packages, project_file = _resolve_pnpm_project(deps_dir, project_dir.path)
        project_files.append(project_file)
        components.extend(_generate_components(project_dir, packages))

    if backend_annotation := create_backend_annotation(components, "pnpm"):
        annotations.append(backend_annotation)

    return RequestOutput.from_obj_list(
        components=components,
        project_files=project_files,
        annotations=annotations,
    )


class PackageJson:
    """Class representing a package.json file."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Initialize a PackageJson object."""
        self.path = path
        self.data = data

    @classmethod
    def from_file(cls, path: Path) -> "PackageJson":
        """Create a PackageJson object from a package.json file."""
        with path.open("r") as f:
            data = json.load(f)
            return cls(path, data)

    @cached_property
    def name(self) -> str | None:
        """Get the 'name' key from the package.json file."""
        return self.data.get("name")

    @cached_property
    def version(self) -> str | None:
        """Get the 'version' key from the package.json file."""
        return self.data.get("version")

    @cached_property
    def dev_dependencies(self) -> set[str]:
        """Get the 'devDependencies' key from the package.json file."""
        deps: dict[str, str] = self.data.get("devDependencies", {})
        return set(deps.keys())


@dataclass(frozen=True)
class PnpmPackage:
    """Class representing a package from a pnpm-lock.yaml file."""

    id: str
    scope: str
    name: str
    version: str
    url: str
    integrity: str | None = None
    dev: bool = False

    @property
    def tarball_path(self) -> str:
        """Get the tarball path for the package."""
        return f"{self.name}-{self.version}.tgz"


class PnpmLock:
    """Class representing a pnpm-lock.yaml file."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Initialize a PnpmLock object."""
        self.path = path
        self.data = data

    @classmethod
    def from_file(cls, path: Path) -> "PnpmLock":
        """Create a PnpmLock object from a pnpm-lock.yaml file."""
        with path.open("r") as f:
            data = yaml.safe_load(f)
            return cls(path, data)

    @cached_property
    def version(self) -> str | None:
        """Get the 'lockfileVersion' key from the pnpm-lock.yaml file."""
        return self.data.get("lockfileVersion")

    @cached_property
    def packages(self) -> dict[str, dict[str, Any]]:
        """Get the 'packages' key from the pnpm-lock.yaml file."""
        return self.data.get("packages", {})

    @cached_property
    def snapshots(self) -> dict[str, dict[str, Any]]:
        """Get the 'snapshots' key from the pnpm-lock.yaml file."""
        return self.data.get("snapshots", {})

    @cached_property
    def optional_dependencies(self) -> set[str]:
        """Parse the optional dependencies from the pnpm-lock.yaml file."""
        return {id for id, data in self.snapshots.items() if data.get("optional", False)}


def _ensure_pnpm_files_exist(project_dir: Path) -> None:
    package_json_path = project_dir.joinpath(PACKAGE_JSON)
    if not package_json_path.exists():
        raise PackageRejected("Missing package.json file", solution=None)

    lockfile_path = project_dir.joinpath(PNPM_LOCK_YAML)
    if not lockfile_path.exists():
        raise LockfileNotFound(
            lockfile_path, solution="Run 'pnpm install' to generate the lockfile."
        )


def _ensure_lockfile_version_is_supported(lockfile: PnpmLock) -> None:
    if lockfile.version != "9.0":
        raise UnsupportedFeature(f"Unsupported 'lockfileVersion' {lockfile.version}", solution=None)


def _parse_package_name_and_version(id: str) -> tuple[str, str, str]:
    """Parse the scope, name and version from a package id."""
    # JSR format: @jsr/scope__name@version or @jsr/name@version
    if id.startswith("@jsr/"):
        full_name, version = id.removeprefix("@jsr/").split("@", 1)
        if "__" in full_name:
            scope, name = full_name.split("__", 1)
            scope = f"@{scope}"
        else:
            scope = ""
            name = full_name

        return scope, name, version

    if "/" in id:
        scope, full_name = id.split("/", 1)
    else:
        scope = ""
        full_name = id

    if "@" not in full_name:
        raise ValueError(f"Invalid package id: {id}")

    name, version = full_name.split("@", 1)
    return scope, name, version


def _resolve_pnpm_project(
    deps_dir: Path, project_dir: Path
) -> tuple[list[PnpmPackage], ProjectFile]:
    """Resolve a pnpm project."""
    lockfile_path = project_dir / PNPM_LOCK_YAML
    lockfile = PnpmLock.from_file(lockfile_path)
    _ensure_lockfile_version_is_supported(lockfile)

    package_json = PackageJson.from_file(project_dir / PACKAGE_JSON)
    dev_dependencies = package_json.dev_dependencies

    packages: list[PnpmPackage] = []
    for id, data in lockfile.packages.items():
        scope, name, version_from_id = _parse_package_name_and_version(id)
        version = data.get("version") or version_from_id
        resolution = data.get("resolution", {})
        integrity = resolution.get("integrity")

        url = _resolve_package_tarball_url(scope, name, version, resolution)

        if url.startswith("file:"):
            log.info("Skipping local dependency %s", id)
            continue

        if id in lockfile.optional_dependencies:
            log.info("Skipping optional dependency %s", id)
            continue

        # TODO: Find also transitive dev dependencies.
        dev = name in dev_dependencies
        packages.append(PnpmPackage(id, scope, name, version, url, integrity, dev))

    _download_packages(packages, deps_dir)
    return packages, _patch_lockfile_with_local_paths(lockfile, packages)


def _construct_npm_registry_tarball_url(scope: str, name: str, version: str) -> str:
    if scope:
        return f"{NPM_REGISTRY_URL}/{scope}/{name}/-/{name}-{version}.tgz"

    return f"{NPM_REGISTRY_URL}/{name}/-/{name}-{version}.tgz"


def _resolve_package_tarball_url(
    scope: str, name: str, version: str, resolution: dict[str, str]
) -> str:
    return resolution.get("tarball") or _construct_npm_registry_tarball_url(scope, name, version)


def _download_packages(packages: list[PnpmPackage], deps_dir: Path) -> None:
    proxy_auth = None
    config = get_config()
    if config.npm.proxy_login and config.npm.proxy_password:
        proxy_auth = aiohttp.BasicAuth(
            config.npm.proxy_login,
            config.npm.proxy_password,
        )

    files_to_download = {package.url: deps_dir / package.tarball_path for package in packages}
    asyncio.run(
        async_download_files(
            files_to_download=files_to_download,
            concurrency_limit=config.runtime.concurrency_limit,
            auth=proxy_auth,
        )
    )

    for package in packages:
        if package.integrity is not None:
            must_match_any_checksum(
                file_path=deps_dir / package.tarball_path,
                expected_checksums=[ChecksumInfo.from_sri(package.integrity)],
            )


def _patch_lockfile_with_local_paths(
    lockfile: PnpmLock, packages: list[PnpmPackage]
) -> ProjectFile:
    """Prepare a pnpm-lock.yaml file for hermetic build."""
    ids = {pkg.id: pkg for pkg in packages}

    for id, data in lockfile.packages.items():
        # only patch the packages that were downloaded
        if id not in ids:
            continue

        pkg = ids[id]
        resolution = data.setdefault("resolution", {})
        resolution["tarball"] = f"file://${{output_dir}}/deps/pnpm/{pkg.tarball_path}"

    return ProjectFile(
        abspath=lockfile.path,
        template=yaml.safe_dump(lockfile.data, sort_keys=False),
    )


def _generate_purl_for(package: PnpmPackage) -> PackageURL:
    """Generate a PURL for a pnpm package."""
    qualifiers: dict[str, str] = {}

    if JSR_REGISTRY_URL in package.url:
        qualifiers["repository_url"] = JSR_REGISTRY_URL

    elif NPM_REGISTRY_URL not in package.url:
        qualifiers["download_url"] = package.url

    return PackageURL(
        type="npm",
        namespace=package.scope.lower(),
        name=package.name.lower(),
        version=package.version,
        qualifiers=qualifiers,
    )


def _get_main_package_component(project_dir: RootedPath) -> Component:
    """Create a component for the main package."""
    package_json_path = project_dir.path / PACKAGE_JSON
    package_json = PackageJson.from_file(package_json_path)

    name = package_json.name
    version = package_json.version
    if name is None:
        raise ValueError(f"Missing 'name' field in the {package_json_path}")

    vcs_url = get_repo_id(project_dir.root).as_vcs_url_qualifier()
    qualifiers = {"vcs_url": vcs_url}
    subpath = str(project_dir.subpath_from_root)

    purl = PackageURL(
        type="npm",
        name=name.lower(),
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
    )
    return Component(name=name, version=version, purl=purl.to_string())


def _generate_components(project_dir: RootedPath, packages: list[PnpmPackage]) -> list[Component]:
    """Generate components for the main package and all dependencies."""
    proxy_url = get_config().npm.proxy_url
    proxy_common = dict(type=PROXY_REF_TYPE, comment=PROXY_COMMENT)

    components = []
    for pkg in packages:
        if proxy_url:
            external_references = [ExternalReference(url=str(proxy_url), **proxy_common)]
        else:
            external_references = None

        properties = PropertySet(npm_development=pkg.dev).to_properties()
        components.append(
            Component(
                name=pkg.name,
                version=pkg.version,
                purl=_generate_purl_for(pkg).to_string(),
                properties=properties,
                external_references=external_references,
            )
        )

    components.append(_get_main_package_component(project_dir))
    return components
