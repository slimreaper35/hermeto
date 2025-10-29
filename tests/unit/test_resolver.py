from pathlib import Path
from unittest import mock

import pytest

from hermeto.core import resolver
from hermeto.core.models.input import Request
from hermeto.core.models.output import BuildConfig, EnvironmentVariable, ProjectFile, RequestOutput
from hermeto.core.models.sbom import Component
from hermeto.core.rooted_path import RootedPath

GOMOD_OUTPUT = RequestOutput.from_obj_list(
    components=[
        Component(
            type="library",
            name="github.com/foo/bar",
            version="v1.0.0",
            purl="pkg:golang/github.com/foo/bar@v1.0.0",
        )
    ],
    environment_variables=[
        EnvironmentVariable(name="GOMODCACHE", value="deps/gomod/pkg/mod", kind="path"),
    ],
    project_files=[
        ProjectFile(abspath="/your/project/go.mod", template="Hello gomod my old friend.")
    ],
)

PIP_OUTPUT = RequestOutput.from_obj_list(
    components=[
        Component(type="library", name="spam", version="1.0.0", purl="pkg:pypi/spam@1.0.0")
    ],
    environment_variables=[
        EnvironmentVariable(name="PIP_INDEX_URL", value="file:///some/path", kind="literal"),
    ],
    project_files=[
        ProjectFile(
            abspath="/your/project/requirements.txt", template="I've come to talk with you again."
        ),
    ],
)

NPM_OUTPUT = RequestOutput.from_obj_list(
    components=[Component(type="library", name="eggs", version="1.0.0", purl="pkg:npm/eggs@1.0.0")],
    environment_variables=[
        EnvironmentVariable(name="CHROMEDRIVER_SKIP_DOWNLOAD", value="true", kind="literal"),
    ],
    project_files=[
        ProjectFile(
            abspath="/your/project/package-lock.json", template="Because a vision softly creeping."
        )
    ],
)

COMBINED_OUTPUT = RequestOutput.from_obj_list(
    components=GOMOD_OUTPUT.components + NPM_OUTPUT.components + PIP_OUTPUT.components,
    environment_variables=(
        GOMOD_OUTPUT.build_config.environment_variables
        + PIP_OUTPUT.build_config.environment_variables
        + NPM_OUTPUT.build_config.environment_variables
    ),
    project_files=(
        GOMOD_OUTPUT.build_config.project_files
        + PIP_OUTPUT.build_config.project_files
        + NPM_OUTPUT.build_config.project_files
    ),
)


@mock.patch("hermeto.core.resolver._resolve_packages")
def test_resolve_packages_updates_project_files(
    mock_resolve_packages: mock.Mock, tmp_path: Path
) -> None:
    request = Request(
        source_dir=tmp_path,
        output_dir=tmp_path,
        packages=[{"type": "pip"}, {"type": "npm"}, {"type": "gomod"}],
    )

    def fake_resolve_packages(request: Request) -> RequestOutput:
        output = COMBINED_OUTPUT
        for project_file in output.build_config.project_files:
            project_file.abspath = request.source_dir.path / project_file.abspath.name

        return output

    mock_resolve_packages.side_effect = fake_resolve_packages

    assert resolver.resolve_packages(request) == COMBINED_OUTPUT
    assert request.source_dir == RootedPath(tmp_path)


@pytest.mark.parametrize(
    "packages",
    [
        pytest.param([{"type": "yarn"}], id="single_package"),
        pytest.param([{"type": "gomod"}, {"type": "pip"}, {"type": "npm"}], id="multiple_packages"),
    ],
)
@mock.patch("hermeto.core.resolver._resolve_packages")
def test_source_dir_copy(
    mock_resolve_packages: mock.Mock,
    packages: list[dict[str, str]],
    tmp_path: Path,
) -> None:
    request = Request(
        source_dir=tmp_path,
        output_dir=tmp_path,
        packages=packages,
    )

    def _resolve_packages(request: Request) -> RequestOutput:
        tmp_dir_name = request.source_dir.path.name

        # assert a temporary directory is being used
        assert tmp_dir_name != tmp_path.name
        assert tmp_dir_name.startswith("tmp")
        assert tmp_dir_name.endswith(".hermeto-source-copy")

        return RequestOutput.empty()

    mock_resolve_packages.side_effect = _resolve_packages

    resolver.resolve_packages(request)

    # assert source_dir is restored to the original value
    assert request.source_dir == RootedPath(tmp_path)


@pytest.mark.parametrize(
    "with_path_replacement",
    (
        pytest.param(True, id="with_path_replacement"),
        pytest.param(False, id="without_path_replacement"),
    ),
)
@mock.patch("hermeto.core.resolver._resolve_packages")
def test_project_files_fix_for_work_copy(
    mock_resolve_packages: mock.Mock,
    tmp_path: Path,
    with_path_replacement: bool,
) -> None:
    request = Request(
        source_dir=tmp_path,
        output_dir=tmp_path,
        packages=[{"type": "yarn"}],
    )

    def _resolve_packages(request: Request) -> RequestOutput:
        # assert request is based on a copy of the source dir
        assert request.source_dir.path != tmp_path
        assert request.source_dir.path.name.endswith(".hermeto-source-copy")

        abspath = request.source_dir.path if with_path_replacement else request.output_dir.path
        return RequestOutput(
            annotations=[],
            components=[],
            build_config=BuildConfig(
                environment_variables=[],
                project_files=[
                    ProjectFile(abspath=abspath / "package.json", template="n/a"),
                ],
            ),
        )

    mock_resolve_packages.side_effect = _resolve_packages
    output = resolver.resolve_packages(request)

    # assert the project file path was corrected to point to the original source dir
    assert output.build_config.project_files[0].abspath == tmp_path / "package.json"


def test_resolve_with_multiple_stable_package_managers(tmp_path: Path) -> None:
    mock_resolve_gomod = mock.Mock(return_value=RequestOutput.empty())
    mock_resolve_pip = mock.Mock(return_value=RequestOutput.empty())

    with (
        mock.patch.dict(
            resolver._package_managers,
            values={"gomod": mock_resolve_gomod, "pip": mock_resolve_pip},
            clear=True,
        ),
    ):
        pip_package_input = mock.Mock()
        pip_package_input.type = "pip"

        gomod_package_input = mock.Mock()
        gomod_package_input.type = "gomod"

        request = mock.Mock()
        request.source_dir = RootedPath(tmp_path)
        request.flags = []
        request.packages = [gomod_package_input, pip_package_input]

        resolver.resolve_packages(request)

        mock_resolve_gomod.assert_has_calls([mock.call(request)])
        mock_resolve_pip.assert_has_calls([mock.call(request)])


def test_mixed_stable_and_experimental_package_managers(tmp_path: Path) -> None:
    """Test that stable and experimental package managers can be used together."""
    mock_stable_handler = mock.Mock(return_value=RequestOutput.empty())
    mock_experimental_handler = mock.Mock(return_value=RequestOutput.empty())

    with mock.patch.dict(
        resolver._package_managers,
        values={"npm": mock_stable_handler, "x-foo": mock_experimental_handler},
        clear=True,
    ):
        stable_package_input = mock.Mock()
        stable_package_input.type = "npm"

        experimental_package_input = mock.Mock()
        experimental_package_input.type = "x-foo"

        request = mock.Mock()
        request.source_dir = RootedPath(tmp_path)
        request.flags = []
        request.packages = [stable_package_input, experimental_package_input]

        result = resolver.resolve_packages(request)

        assert result == RequestOutput.empty()
        mock_stable_handler.assert_called_once_with(request)
        mock_experimental_handler.assert_called_once_with(request)
