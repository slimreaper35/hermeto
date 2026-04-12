# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path

from hermeto.core.package_managers.javascript.pnpm.main import _patch_lockfile_with_local_paths
from hermeto.core.package_managers.javascript.pnpm.project import PnpmLock, PnpmPackage


def test_patch_lockfile_with_local_paths(tmp_path: Path) -> None:
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

    project_file = _patch_lockfile_with_local_paths(lockfile, packages)

    assert project_file.abspath == lockfile.path
    assert (
        lockfile.packages["a@1.0.0"]["resolution"]["tarball"]
        == "file://${output_dir}/deps/pnpm/a-1.0.0.tgz"
    )
    assert (
        lockfile.packages["@scope/b@2.0.0"]["resolution"]["tarball"]
        == "file://${output_dir}/deps/pnpm/scope-b-2.0.0.tgz"
    )
