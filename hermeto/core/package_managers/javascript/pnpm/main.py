# SPDX-License-Identifier: GPL-3.0-only
import asyncio
import logging
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import yaml

from hermeto.core.checksum import ChecksumInfo, must_match_any_checksum
from hermeto.core.config import ProxyUrl, get_config
from hermeto.core.models.input import Request
from hermeto.core.models.output import Annotation, Component, ProjectFile, RequestOutput
from hermeto.core.models.sbom import create_backend_annotation
from hermeto.core.package_managers.general import async_download_files
from hermeto.core.package_managers.javascript.pnpm.project import (
    NPM_REGISTRY_URL,
    PnpmLock,
    PnpmPackage,
    parse_packages,
)
from hermeto.core.package_managers.javascript.pnpm.resolver import _generate_sbom_components

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
        log.info("Fetching pnpm dependencies at %s", project_dir.path)

        lockfile = PnpmLock.from_dir(project_dir.path)
        packages, project_file = _resolve_pnpm_project(deps_dir, lockfile)
        project_files.append(project_file)
        components.extend(_generate_sbom_components(project_dir, lockfile, packages))

    if backend_annotation := create_backend_annotation(components, "pnpm"):
        annotations.append(backend_annotation)

    return RequestOutput.from_obj_list(
        components=components,
        project_files=project_files,
        annotations=annotations,
    )


def _resolve_pnpm_project(
    deps_dir: Path, lockfile: PnpmLock
) -> tuple[list[PnpmPackage], ProjectFile]:
    """Resolve a pnpm project."""
    packages = parse_packages(lockfile)
    non_local = [package for package in packages if not package.url.startswith("file:")]
    _download_packages(non_local, deps_dir)
    return packages, _patch_lockfile_with_local_paths(lockfile, non_local)


def _patch_url_to_point_to_proxy(url: str, proxy_url: ProxyUrl) -> str:
    """
    >>> _patch_url_to_point_to_proxy('https://registry.npmjs.org/foo/-/foo-1.0.0.tgz', 'http://proxy.example.com')
    'http://proxy.example.com/foo/-/foo-1.0.0.tgz'
    >>> _patch_url_to_point_to_proxy('https://registry.npmjs.org/foo/-/foo-1.0.0.tgz', 'http://proxy.example.com/')
    'http://proxy.example.com/foo/-/foo-1.0.0.tgz'
    """
    str_proxy_url = str(proxy_url)
    str_proxy_url = str_proxy_url if str_proxy_url[-1] == "/" else str_proxy_url + "/"
    url_path = urlparse(url).path.removeprefix("/")
    return str_proxy_url + url_path


def _download_packages(packages: list[PnpmPackage], deps_dir: Path) -> None:
    proxy_auth = None
    config = get_config()
    concurrency_limit = config.runtime.concurrency_limit

    if config.npm.proxy_login is not None and config.npm.proxy_password is not None:
        proxy_auth = aiohttp.BasicAuth(config.npm.proxy_login, config.npm.proxy_password)

    files_with_auth = {}
    files_without_auth = {}
    for package in packages:
        if proxy_auth is not None and NPM_REGISTRY_URL in package.url:
            actual_url = _patch_url_to_point_to_proxy(package.url, config.npm.proxy_url)
            files_with_auth[actual_url] = deps_dir / package.tarball_name
        else:
            files_without_auth[package.url] = deps_dir / package.tarball_name

    async def download_all() -> None:
        await async_download_files(files_with_auth, concurrency_limit, auth=proxy_auth)
        await async_download_files(files_without_auth, concurrency_limit)

    asyncio.run(download_all())

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
