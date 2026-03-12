# SPDX-License-Identifier: GPL-3.0-only
import asyncio
import json
import logging
import subprocess
from collections import UserDict
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from itertools import chain
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
import yaml
from packageurl import PackageURL

from hermeto.core.checksum import ChecksumInfo, must_match_any_checksum
from hermeto.core.config import ProxyUrl, get_config
from hermeto.core.errors import LockfileNotFound, UnsupportedFeature
from hermeto.core.models.input import Mode, Request
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
        packages, project_file = _resolve_pnpm_project(deps_dir, project_dir.path)
        project_files.append(project_file)
        components.extend(_generate_sbom_components(project_dir, packages, request.mode))

    if backend_annotation := create_backend_annotation(components, "pnpm"):
        annotations.append(backend_annotation)

    return RequestOutput.from_obj_list(
        components=components,
        project_files=project_files,
        annotations=annotations,
    )


class PackageJson(UserDict):
    """Class representing package.json files."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Initialize a PackageJson object."""
        self.path = path
        super().__init__(data)

    @classmethod
    def from_file(cls, path: Path) -> "PackageJson":
        """Create a PackageJson object from a package.json file."""
        with path.open("r") as f:
            data = json.load(f)
            return cls(path, data)

    @classmethod
    def from_dir(cls, path: Path) -> "PackageJson":
        """Create a PackageJson object from a package.json file."""
        return cls.from_file(path.joinpath("package.json"))

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
    def tarball_name(self) -> str:
        """Get the tarball name for the package."""
        if self.scope:
            scope = self.scope.removeprefix("@")
            return f"{scope}-{self.name}-{self.version}.tgz"

        return f"{self.name}-{self.version}.tgz"


class PnpmLock(UserDict):
    """Class representing a pnpm-lock.yaml file."""

    def __init__(self, path: Path, data: dict[str, Any]) -> None:
        """Initialize a PnpmLock object."""
        self.path = path
        self.data = data

    @classmethod
    def from_file(cls, path: Path) -> "PnpmLock":
        """Create a PnpmLock object from a pnpm-lock.yaml file."""
        if not path.exists():
            raise LockfileNotFound(
                path, solution="Run 'pnpm install' to generate the pnpm-lock.yaml file."
            )

        with path.open("r") as f:
            data = yaml.safe_load(f)
            return cls(path, data)

    @classmethod
    def from_dir(cls, path: Path) -> "PnpmLock":
        """Create a PnpmLock object from a pnpm-lock.yaml file."""
        return cls.from_file(path.joinpath(PNPM_LOCK_YAML))

    @classmethod
    def from_pnpm_list(cls, dir: Path) -> "PnpmLock":
        """Create a PnpmLock object by running the `pnpm list` command."""
        cmd = ["pnpm", "list", "--lockfile-only", "--json", "--depth", "Infinity", "--no-color"]
        result = subprocess.run(cmd, cwd=dir, capture_output=True, text=True)
        path = dir / PNPM_LOCK_YAML
        return cls(path, json.loads(result.stdout))

    @cached_property
    def packages(self) -> dict[str, dict[str, Any]]:
        """Return the 'packages' key from the pnpm-lock.yaml file."""
        return self.data.get("packages", {})

    @cached_property
    def optional_dependencies(self) -> set[str]:
        """Return the set of optional dependencies."""
        snapshots: dict[str, dict[str, Any]] = self.get("snapshots", {})
        return {id for id, data in snapshots.items() if data.get("optional", False)}


def _ensure_lockfile_version_is_supported(lockfile: PnpmLock) -> None:
    version = lockfile.data.get("lockfileVersion")
    if version != "9.0":
        raise UnsupportedFeature(f"Unsupported 'lockfileVersion' {version}", solution=None)


def _parse_package_name_and_version(id: str) -> tuple[str, str, str]:
    """
    Parse the scope, name and version from a package id.

    >>> _parse_package_name_and_version("foo@https://codeload.github.com/org/repo/tar.gz/abcdefg")
    ('', 'foo', 'https://codeload.github.com/org/repo/tar.gz/abcdefg')
    """
    # JSR format: @jsr/scope__name@version or @jsr/name@version
    if id.startswith("@jsr/"):
        full_name, version = id.removeprefix("@jsr/").split("@", maxsplit=1)
        if "__" in full_name:
            scope, name = full_name.split("__", 1)
            scope = f"@{scope}"
        else:
            scope = ""
            name = full_name

        return scope, name, version

    # Scoped package: @scope/name@version
    if id.count("@") == 2:
        scope, full_name = id.split("/", maxsplit=1)
        name, version = full_name.split("@", maxsplit=1)
        return scope, name, version

    # Unscoped package: name@version OR name@https://codeload.github.com/org/repo/tar.gz/commit
    if "@" not in id:
        raise ValueError(f"Invalid package id: {id}")

    name, version = id.split("@", maxsplit=1)
    return "", name, version


@contextmanager
def _hidden_cjs_files(project_dir: Path) -> Generator[None, None, None]:
    """Temporarily hide "dangerous" pnpm files from the project directory."""
    # .npmrc can be used to point to a custom pnpmfile
    files = (".pnpmfile.cjs", ".pnpmfile.mjs", ".npmrc")
    contents: list[tuple[Path, str]] = []
    for file in files:
        path = project_dir.joinpath(file)
        if path.exists():
            contents.append((path, path.read_text()))
            path.unlink()

    try:
        yield
    finally:
        for path, content in contents:
            path.write_text(content)


def _resolve_pnpm_project(
    deps_dir: Path, project_dir: Path
) -> tuple[list[PnpmPackage], ProjectFile]:
    """Resolve a pnpm project."""
    package_json = PackageJson.from_dir(project_dir)
    lockfile = PnpmLock.from_dir(project_dir)
    _ensure_lockfile_version_is_supported(lockfile)

    packages = _parse_packages(package_json, lockfile)
    non_local = [package for package in packages if not package.url.startswith("file:")]
    _download_packages(non_local, deps_dir)
    return packages, _patch_lockfile_with_local_paths(lockfile, non_local)


def _parse_packages(package_json: PackageJson, lockfile: PnpmLock) -> list[PnpmPackage]:
    dev_deps = package_json.dev_dependencies
    result: list[PnpmPackage] = []

    for id, data in lockfile.packages.items():
        scope, name, version_from_id = _parse_package_name_and_version(id)
        version = data.get("version") or version_from_id
        resolution = data.get("resolution", {})
        integrity = resolution.get("integrity")

        if id in lockfile.optional_dependencies:
            log.debug("Skipping optional dependency %s", id)
            continue

        url = _resolve_package_tarball_url(scope, name, version, resolution)
        # TODO: Find also transitive dev dependencies.
        dev = name in dev_deps
        result.append(PnpmPackage(id, scope, name, version, url, integrity, dev))

    return result


def _construct_npm_registry_tarball_url(scope: str, name: str, version: str) -> str:
    if scope:
        return f"{NPM_REGISTRY_URL}/{scope}/{name}/-/{name}-{version}.tgz"

    return f"{NPM_REGISTRY_URL}/{name}/-/{name}-{version}.tgz"


def _resolve_package_tarball_url(
    scope: str, name: str, version: str, resolution: dict[str, str]
) -> str:
    return resolution.get("tarball") or _construct_npm_registry_tarball_url(scope, name, version)


def _patch_url_to_point_to_proxy(url: str, proxy_url: ProxyUrl) -> str:
    """
    Convert 'https://registry.npmjs.org/foo/-/foo-1.3.8.tgz' to '<proxy-address>/foo/-/foo-1.3.8.tgz'.
    """
    str_proxy_url = str(proxy_url)
    str_proxy_url = str_proxy_url if str_proxy_url[-1] == "/" else str_proxy_url + "/"
    url_path = urlparse(url).path.removeprefix("/")
    return str_proxy_url + url_path


def _download_packages(packages: list[PnpmPackage], deps_dir: Path) -> None:
    proxy_auth = None
    config = get_config()
    if config.npm.proxy_login and config.npm.proxy_password:
        proxy_auth = aiohttp.BasicAuth(
            config.npm.proxy_login,
            config.npm.proxy_password,
        )

    files_with_auth = {}
    files_without_auth = {}
    for package in packages:
        if proxy_auth is not None and NPM_REGISTRY_URL in package.url:
            actual_url = _patch_url_to_point_to_proxy(package.url, config.npm.proxy_url)
            files_with_auth[actual_url] = deps_dir / package.tarball_name
        else:
            files_without_auth[package.url] = deps_dir / package.tarball_name

    asyncio.run(
        async_download_files(
            files_to_download=files_with_auth,
            concurrency_limit=config.runtime.concurrency_limit,
            auth=proxy_auth,
        )
    )

    asyncio.run(
        async_download_files(
            files_to_download=files_without_auth,
            concurrency_limit=config.runtime.concurrency_limit,
            auth=None,
        )
    )

    for package in packages:
        if package.integrity is not None:
            must_match_any_checksum(
                file_path=deps_dir / package.tarball_name,
                expected_checksums=[ChecksumInfo.from_sri(package.integrity)],
            )


def _patch_lockfile_with_local_paths(
    lockfile: PnpmLock, packages: list[PnpmPackage]
) -> ProjectFile:
    """Prepare a pnpm-lock.yaml file for hermetic build."""
    for package in packages:
        data = lockfile.packages[package.id]
        resolution = data.setdefault("resolution", {})
        resolution["tarball"] = f"file://${{output_dir}}/deps/pnpm/{package.tarball_name}"

    return ProjectFile(
        abspath=lockfile.path,
        template=yaml.safe_dump(lockfile.data, sort_keys=False),
    )


def _get_vcs_url(project_dir: RootedPath) -> str:
    """Get VCS URL qualifier for a PURL (package URL) from a project directory."""
    return get_repo_id(project_dir.root).as_vcs_url_qualifier()


def _get_main_component(project_dir: RootedPath, vcs_url: str) -> Component:
    """Create a component for the main package."""
    package_json = PackageJson.from_dir(project_dir.path)

    name = package_json.get("name")
    version = package_json.get("version")
    if name is None:
        raise ValueError(f"Missing 'name' field in the {package_json.path}")

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


def _get_workspace_paths(project_dir: RootedPath) -> list[Path]:
    """Resolve workspace paths from pnpm-workspace.yaml file."""
    pnpm_workspace_path = project_dir.path / "pnpm-workspace.yaml"
    if not pnpm_workspace_path.exists():
        return []

    with pnpm_workspace_path.open("r") as f:
        pnpm_workspace = yaml.safe_load(f)
        globs = pnpm_workspace.get("packages", [])

    def all_paths_matching(glob: str) -> Generator[Path, None, None]:
        return (path.resolve() for path in project_dir.path.glob(glob) if path.is_dir())

    return list(chain.from_iterable(map(all_paths_matching, globs)))


def _get_workspace_components(project_dir: RootedPath, vcs_url: str) -> list[Component]:
    """Create components for the workspace packages."""
    components = []

    workspace_paths = _get_workspace_paths(project_dir)
    for workspace_path in workspace_paths:
        package_json = PackageJson.from_dir(workspace_path)
        name = package_json.get("name")
        version = package_json.get("version")
        if name is None:
            raise ValueError(f"Missing 'name' field in the {package_json.path}")

        qualifiers = {"vcs_url": vcs_url}
        subpath = str(workspace_path.relative_to(project_dir.path))

        purl = PackageURL(
            type="npm",
            name=name.lower(),
            version=version,
            qualifiers=qualifiers,
            subpath=subpath,
        )
        components.append(Component(name=name, version=version, purl=purl.to_string()))

    return components


def _generate_purl_for(_project_dir: RootedPath, package: PnpmPackage, vcs_url: str) -> PackageURL:
    """Generate a PURL for a pnpm package."""
    qualifiers: dict[str, str] = {}
    subpath = None

    if package.url.startswith("file:"):
        subpath = package.url.removeprefix("file:")
        qualifiers["vcs_url"] = vcs_url

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


def _generate_sbom_components(
    project_dir: RootedPath,
    packages: list[PnpmPackage],
    mode: Mode,  # noqa
) -> list[Component]:
    """Generate components for the main package and all dependencies."""
    vcs_url = _get_vcs_url(project_dir)
    proxy_url = get_config().npm.proxy_url
    proxy_common = dict(type=PROXY_REF_TYPE, comment=PROXY_COMMENT)

    components = []
    for package in packages:
        if proxy_url:
            external_references = [ExternalReference(url=str(proxy_url), **proxy_common)]
        else:
            external_references = None

        purl = _generate_purl_for(project_dir, package, vcs_url)
        properties = PropertySet(npm_development=package.dev).to_properties()
        components.append(
            Component(
                name=package.name,
                version=package.version,
                purl=purl.to_string(),
                properties=properties,
                external_references=external_references,
            )
        )

    components.append(_get_main_component(project_dir, vcs_url))
    components.extend(_get_workspace_components(project_dir, vcs_url))
    return components
