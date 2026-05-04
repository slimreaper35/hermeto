# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from unittest import mock

import yaml

from hermeto.core.package_managers.javascript.pnpm.main import (
    _prepare_lockfile_for_hermetic_build,
    _resolve_pnpm_project,
)
from hermeto.core.package_managers.javascript.pnpm.project import PnpmLock, PnpmPackage
from hermeto.core.package_managers.npm import NPM_REGISTRY_URL


@mock.patch(
    "hermeto.core.package_managers.javascript.pnpm.main._prepare_lockfile_for_hermetic_build"
)
@mock.patch("hermeto.core.package_managers.javascript.pnpm.main._download_resolved_packages")
@mock.patch("hermeto.core.package_managers.javascript.pnpm.main.parse_packages")
def test_resolve_pnpm_project_skips_local_packages(
    mock_parse_packages: mock.Mock,
    mock_download_resolved_packages: mock.Mock,
    mock_prepare_lockfile_for_hermetic_build: mock.Mock,
    tmp_path: Path,
) -> None:
    remote = PnpmPackage("a@1.0.0", "", "a", "1.0.0", f"{NPM_REGISTRY_URL}/a/-/a-1.0.0.tgz")
    local = PnpmPackage("b@1.0.0", "", "b", "1.0.0", "file:packages/b.tgz")
    mock_parse_packages.return_value = [remote, local]

    _resolve_pnpm_project(tmp_path, mock.Mock())
    mock_download_resolved_packages.assert_called_once_with([remote], tmp_path)
    mock_prepare_lockfile_for_hermetic_build.assert_called_once_with(mock.ANY, [remote])


def test_prepare_lockfile_for_hermetic_build(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": "9.0",
        "packages": {
            "a@1.0.0": {"resolution": {"integrity": "sha512-abc"}},
            "@scope/b@2.0.0": {"resolution": {"integrity": "sha512-def"}},
        },
    }
    lockfile = PnpmLock(path=tmp_path / "pnpm-lock.yaml", data=data)
    packages = [
        PnpmPackage(
            "a@1.0.0",
            "",
            "a",
            "1.0.0",
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "sha512-abc",
        ),
        PnpmPackage(
            "@scope/b@2.0.0",
            "scope",
            "b",
            "2.0.0",
            "https://registry.npmjs.org/@scope/b/-/b-2.0.0.tgz",
            "sha512-def",
        ),
    ]

    project_file = _prepare_lockfile_for_hermetic_build(lockfile, packages)

    assert project_file.abspath == lockfile.path
    assert project_file.template == yaml.safe_dump(
        {
            "lockfileVersion": "9.0",
            "packages": {
                "a@1.0.0": {
                    "resolution": {
                        "integrity": "sha512-abc",
                        "tarball": "file://${output_dir}/deps/pnpm/a-1.0.0.tgz",
                    }
                },
                "@scope/b@2.0.0": {
                    "resolution": {
                        "integrity": "sha512-def",
                        "tarball": "file://${output_dir}/deps/pnpm/scope-b-2.0.0.tgz",
                    }
                },
            },
        },
        sort_keys=False,
    )
