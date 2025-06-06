import enum
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Callable, Literal, Optional, TypeVar, Union

import pydantic
from typing_extensions import Self

from hermeto import APP_NAME
from hermeto.core.errors import InvalidInput
from hermeto.core.models.validators import check_sane_relpath, unique
from hermeto.core.rooted_path import PathOutsideRoot, RootedPath

if TYPE_CHECKING:
    from pydantic.error_wrappers import ErrorDict


log = logging.getLogger(__name__)

T = TypeVar("T")
ModelT = TypeVar("ModelT", bound=pydantic.BaseModel)


def parse_user_input(to_model: Callable[[T], ModelT], input_obj: T) -> ModelT:
    """Parse user input into a model, re-raise validation errors as InvalidInput."""
    try:
        return to_model(input_obj)
    except pydantic.ValidationError as e:
        raise InvalidInput(_present_user_input_error(e)) from e


def _present_user_input_error(validation_error: pydantic.ValidationError) -> str:
    """Make a slightly nicer representation of a pydantic.ValidationError.

    Compared to pydantic's default message:
    - don't show the model name, just say "user input"
    - don't show the underlying error type (e.g. "type=value_error.const")
    """
    errors = validation_error.errors()
    n_errors = len(errors)

    def show_error(error: "ErrorDict") -> str:
        location = " -> ".join(map(str, error["loc"]))
        message = error["msg"]

        if location != "__root__":
            message = f"{location}\n  {message}"

        return message

    header = f"{n_errors} validation error{'' if n_errors == 1 else 's'} for user input"
    details = "\n".join(map(show_error, errors))
    return f"{header}\n{details}"


# Supported package managers
PackageManagerType = Literal["bundler", "cargo", "generic", "gomod", "npm", "pip", "rpm", "yarn"]

Flag = Literal[
    "cgo-disable", "dev-package-managers", "force-gomod-tidy", "gomod-vendor", "gomod-vendor-check"
]


class Mode(str, enum.Enum):
    """Represents a global CLI option to relax input expectations and requirements checks."""

    STRICT = "strict"
    PERMISSIVE = "permissive"

    def __str__(self) -> str:
        return self.value


class _PackageInputBase(pydantic.BaseModel, extra="forbid"):
    """Common input attributes accepted for all package types."""

    type: PackageManagerType
    path: Path = Path(".")

    @pydantic.field_validator("path")
    def _path_is_relative(cls, path: Path) -> Path:
        return check_sane_relpath(path)


class SSLOptions(pydantic.BaseModel, extra="forbid"):
    """SSL options model.

    Defines extra options fields for client TLS authentication.
    """

    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    ca_bundle: Optional[str] = None
    ssl_verify: bool = True

    @pydantic.field_validator("client_key", "client_cert", "ca_bundle")
    @classmethod
    def _validate_auth_file_paths(cls, val: str, info: pydantic.ValidationInfo) -> Optional[str]:
        if val is None:
            return val

        if not Path(val).is_file():
            raise ValueError(
                (
                    f"Specified ssl auth file '{info.field_name}':'{val}' is not a regular file.",
                    "Make sure the file exists and that it has correct permissions.",
                )
            )

        return val

    @pydantic.model_validator(mode="after")
    def _validate_ssl_options(self) -> Self:
        cert_and_key = (self.client_cert, self.client_key)
        if any(cert_and_key) and not all(cert_and_key):
            raise ValueError(
                "When using client certificates, client_key and client_cert must both be provided."
            )

        return self


class BundlerPackageInput(_PackageInputBase):
    """Accepted input for a bundler package."""

    type: Literal["bundler"]
    allow_binary: bool = False


class CargoPackageInput(_PackageInputBase):
    """Accepted input for a cargo package."""

    type: Literal["cargo"]


class GenericPackageInput(_PackageInputBase):
    """Accepted input for generic package."""

    type: Literal["generic"]
    lockfile: Optional[Path] = None


class GomodPackageInput(_PackageInputBase):
    """Accepted input for a gomod package."""

    type: Literal["gomod"]


class NpmPackageInput(_PackageInputBase):
    """Accepted input for a npm package."""

    type: Literal["npm"]


class PipPackageInput(_PackageInputBase):
    """Accepted input for a pip package."""

    type: Literal["pip"]
    requirements_files: Optional[list[Path]] = None
    requirements_build_files: Optional[list[Path]] = None
    allow_binary: bool = False

    @pydantic.field_validator("requirements_files", "requirements_build_files")
    def _no_explicit_none(cls, paths: Optional[list[Path]]) -> list[Path]:
        """Fail if the user explicitly passes None."""
        if paths is None:
            # Note: same error message as pydantic's default
            raise ValueError("none is not an allowed value")
        return paths

    @pydantic.field_validator("requirements_files", "requirements_build_files")
    def _requirements_file_path_is_relative(cls, paths: list[Path]) -> list[Path]:
        for p in paths:
            check_sane_relpath(p)
        return paths


class ExtraOptions(pydantic.BaseModel, extra="forbid"):
    """Global package manager extra options model.

    This model takes care of carrying and parsing various kind of extra options that need to be
    passed through to CLI commands/services we interact with underneath to tweak their behaviour
    rather than our own. Each option set is namespaced by the corresponding tool/service it is
    related to.

    TODO: Enable this globally for all pkg managers not just the RpmPackageInput model.
    """

    dnf: Optional[dict[Union[Literal["main"], str], dict[str, Any]]] = None
    ssl: Optional[SSLOptions] = None

    @pydantic.model_validator(mode="before")
    def _validate_dnf_options(cls, data: Any, info: pydantic.ValidationInfo) -> Any:
        """DNF options model.

        DNF options can be provided via 2 'streams':
            1) global /etc/dnf/dnf.conf OR
            2) /etc/yum.repos.d/.repo files

        Config options are specified via INI format based on sections. There are 2 types of sections:
            1) global 'main' - either global repo options or DNF control-only options
                - NOTE: there must always ever be a single "main" section

            2) <repoid> sections - options tied specifically to a given defined repo

        [1] https://man7.org/linux/man-pages/man5/dnf.conf.5.html
        """

        def _raise_unexpected_type(repr_: str, *prefixes: str) -> None:
            loc = ".".join(prefixes + (repr_,))
            raise ValueError(f"Unexpected data type for '{loc}' in input JSON: expected 'dict'")

        if "dnf" not in data:
            return data

        prefixes: list[str] = ["options", "dnf"]
        dnf_opts = data["dnf"]

        if not isinstance(dnf_opts, dict):
            _raise_unexpected_type(str(dnf_opts), *prefixes)

        for repo, repo_options in dnf_opts.items():
            prefixes.append(repo)
            if not isinstance(repo_options, dict):
                _raise_unexpected_type(str(repo_options), *prefixes)

        return data


class RpmPackageInput(_PackageInputBase):
    """Accepted input for a rpm package."""

    type: Literal["rpm"]
    include_summary_in_sbom: bool = False
    options: Optional[ExtraOptions] = None


class YarnPackageInput(_PackageInputBase):
    """Accepted input for a yarn package."""

    type: Literal["yarn"]


PackageInput = Annotated[
    Union[
        BundlerPackageInput,
        CargoPackageInput,
        GenericPackageInput,
        GomodPackageInput,
        NpmPackageInput,
        PipPackageInput,
        RpmPackageInput,
        YarnPackageInput,
    ],
    # https://pydantic-docs.helpmanual.io/usage/types/#discriminated-unions-aka-tagged-unions
    pydantic.Field(discriminator="type"),
]


class Request(pydantic.BaseModel):
    """Holds all data needed for the processing of a single request."""

    source_dir: RootedPath
    output_dir: RootedPath
    packages: list[PackageInput]
    flags: frozenset[Flag] = frozenset()
    mode: Mode = Mode.STRICT

    @pydantic.field_validator("packages")
    def _unique_packages(cls, packages: list[PackageInput]) -> list[PackageInput]:
        """De-duplicate the packages to be processed."""
        return unique(packages, by=lambda pkg: (pkg.type, pkg.path))

    @pydantic.field_validator("packages")
    def _check_packages_paths(
        cls, packages: list[PackageInput], info: pydantic.ValidationInfo
    ) -> list[PackageInput]:
        """Check that package paths are existing subdirectories."""
        # Note that any of the other fields may have failed the validation (hence None), because
        # pydantic always validates all fields without failing early [1]
        # [1] https://github.com/pydantic/pydantic/discussions/9533#discussioncomment-9620872
        source_dir: Optional[RootedPath] = info.data.get("source_dir", None)
        if source_dir is not None:
            for p in packages:
                try:
                    abspath = source_dir.join_within_root(p.path)
                except PathOutsideRoot:
                    raise ValueError(
                        f"package path (a symlink?) leads outside source directory: {p.path}"
                    )
                if not abspath.path.is_dir():
                    raise ValueError(
                        f"package path does not exist (or is not a directory): {p.path}"
                    )
        return packages

    @pydantic.field_validator("flags")
    def _deprecation_warning(cls, flags: frozenset[Flag]) -> frozenset[Flag]:
        """Print a deprecation warning for flags, if needed."""
        if "gomod-vendor" in flags:
            log.warning(
                "The `gomod-vendor` flag is deprecated and will be removed in future versions. "
                "Note that it will no longer perform automatic vendoring, so in case vendoring "
                "is needed, it needs to be manually added to the source repository."
            )

        if "gomod-vendor-check" in flags:
            log.warning(
                "The `gomod-vendor-check` flag is deprecated and will be removed in future versions. "
                f"Its use is no longer necessary, {APP_NAME} will automatically check the contents of the "
                "vendor directory in case it is present."
            )

        return flags

    @pydantic.field_validator("packages")
    def _packages_not_empty(cls, packages: list[PackageInput]) -> list[PackageInput]:
        """Check that the packages list is not empty."""
        if len(packages) == 0:
            raise ValueError("at least one package must be defined, got an empty list")
        return packages

    @property
    def bundler_packages(self) -> list[BundlerPackageInput]:
        """Get the bundler packages specified for this request."""
        return self._packages_by_type(BundlerPackageInput)

    @property
    def cargo_packages(self) -> list[CargoPackageInput]:
        """Get the cargo packages specified for this request."""
        return self._packages_by_type(CargoPackageInput)

    @property
    def generic_packages(self) -> list[GenericPackageInput]:
        """Get the generic packages specified for this request."""
        return self._packages_by_type(GenericPackageInput)

    @property
    def gomod_packages(self) -> list[GomodPackageInput]:
        """Get the gomod packages specified for this request."""
        return self._packages_by_type(GomodPackageInput)

    @property
    def npm_packages(self) -> list[NpmPackageInput]:
        """Get the npm packages specified for this request."""
        return self._packages_by_type(NpmPackageInput)

    @property
    def pip_packages(self) -> list[PipPackageInput]:
        """Get the pip packages specified for this request."""
        return self._packages_by_type(PipPackageInput)

    @property
    def rpm_packages(self) -> list[RpmPackageInput]:
        """Get the rpm packages specified for this request."""
        return self._packages_by_type(RpmPackageInput)

    @property
    def yarn_packages(self) -> list[YarnPackageInput]:
        """Get the yarn packages specified for this request."""
        return self._packages_by_type(YarnPackageInput)

    def _packages_by_type(self, pkgtype: type[T]) -> list[T]:
        return [package for package in self.packages if isinstance(package, pkgtype)]
