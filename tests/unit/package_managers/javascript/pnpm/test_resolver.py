# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path

from hermeto.core.package_managers.javascript.pnpm.project import PnpmLock
from hermeto.core.package_managers.javascript.pnpm.resolver import _resolve_dev_dependencies


def test_resolve_dev_dependencies(tmp_path: Path) -> None:
    lockfile = PnpmLock(
        path=tmp_path / "pnpm-lock.yaml",
        data={
            "lockfileVersion": "9.0",
            "importers": {
                ".": {
                    "dependencies": {
                        "a": {"version": "1.0.0"},
                    },
                    "devDependencies": {
                        "c": {"version": "3.0.0"},
                    },
                },
            },
            "snapshots": {
                "a@1.0.0": {},
                "b@2.0.0": {},
                "c@3.0.0": {"dependencies": {"d": "4.0.0", "e": "5.0.0"}},
                "d@4.0.0": {"dependencies": {"e": "5.0.0"}},
                "e@5.0.0": {},
            },
        },
    )
    assert _resolve_dev_dependencies(lockfile) == {"c@3.0.0", "d@4.0.0", "e@5.0.0"}


def test_resolve_no_dev_dependencies(tmp_path: Path) -> None:
    lockfile = PnpmLock(
        path=tmp_path / "pnpm-lock.yaml",
        data={"lockfileVersion": "9.0", "importers": {".": {}}, "snapshots": {}},
    )
    assert _resolve_dev_dependencies(lockfile) == set()
