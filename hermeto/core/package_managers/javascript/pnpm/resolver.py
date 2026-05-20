# SPDX-License-Identifier: GPL-3.0-only
import json
from collections import UserDict
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from hermeto.core.config import get_config
from hermeto.core.constants import Mode
from hermeto.core.errors import NotAGitRepo
from hermeto.core.models.sbom import PROXY_COMMENT, Component, ExternalReference
from hermeto.core.package_managers.general import get_vcs_qualifiers
from hermeto.core.package_managers.javascript.pnpm.project import PnpmPackage
from hermeto.core.package_managers.npm import NPM_REGISTRY_URL, is_from_npm_registry
from hermeto.core.rooted_path import RootedPath

JSR_REGISTRY_URL = "https://registry.jsr.io"


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


def generate_sbom_components(
    project_dir: RootedPath, packages: list[PnpmPackage]
) -> list[Component]:
    """Generate SBOM components for the project."""
    config = get_config()
    try:
        vcs_qualifiers = get_vcs_qualifiers(project_dir.root)
    except NotAGitRepo:
        if config.mode == Mode.PERMISSIVE:
            vcs_qualifiers = None
        else:
            raise

    result = []
    result.extend(_create_lockfile_components(packages, vcs_qualifiers))
    result.append(_create_root_component(project_dir, vcs_qualifiers))
    return result


def _create_lockfile_components(
    packages: list[PnpmPackage], vcs_qualifiers: dict[str, str] | None
) -> list[Component]:
    config = get_config()
    proxy_url = config.pnpm.proxy_url

    components = []
    for package in packages:
        if is_from_npm_registry(package.url) and proxy_url is not None:
            external_references = [ExternalReference(url=str(proxy_url), comment=PROXY_COMMENT)]
        else:
            external_references = None

        purl = _generate_purl_for(package, vcs_qualifiers)
        components.append(
            Component(
                name=package.name,
                version=package.version,
                purl=purl.to_string(),
                external_references=external_references,
            )
        )

    return components


def _generate_purl_for(package: PnpmPackage, vcs_qualifiers: dict[str, str] | None) -> PackageURL:
    """Generate a PURL for the given package."""
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


def _create_root_component(
    project_dir: RootedPath, vcs_qualifiers: dict[str, str] | None
) -> Component:
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
