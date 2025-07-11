# SPDX-License-Identifier: GPL-3.0-or-later
import logging
import re
import tarfile
import tempfile
from os import PathLike
from pathlib import Path
from typing import Any, NamedTuple, Union
from urllib.parse import ParseResult, SplitResult, urlparse, urlsplit

from git.exc import InvalidGitRepositoryError, NoSuchPathError
from git.repo import Repo

from hermeto import APP_NAME
from hermeto.core.errors import FetchError, NotAGitRepo, UnsupportedFeature

log = logging.getLogger(__name__)


class RepoID(NamedTuple):
    """The properties which uniquely identify a repository at a specific commit."""

    origin_url: str
    commit_id: str

    @property
    def parsed_origin_url(self) -> SplitResult:
        """Get the url as a urllib.parse.SplitResult."""
        return urlsplit(self.origin_url)

    def as_vcs_url_qualifier(self) -> str:
        """Turn this RepoID into a 'vcs_url' qualifier as defined by the purl spec.

        See https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#known-qualifiers-keyvalue-pairs
        """
        return f"git+{self.origin_url}@{self.commit_id}"


def get_repo_id(repo: Union[str, PathLike[str], Repo]) -> RepoID:
    """Get the RepoID for a git.Repo object or a git directory.

    If the remote url is an scp-style [user@]host:path, convert it into ssh://[user@]host/path.

    See `man git-clone` (GIT URLS) for some of the url formats that git supports.
    """
    if isinstance(repo, (str, PathLike)):
        try:
            repo = Repo(repo, search_parent_directories=True)
        except (InvalidGitRepositoryError, NoSuchPathError):
            raise NotAGitRepo(
                f"The provided path {repo} cannot be processed as a valid git repository.",
                solution=(
                    "Please ensure that the path is correct and that it is a valid git repository."
                ),
            )

    try:
        origin = repo.remote("origin")
    except ValueError:
        raise UnsupportedFeature(
            f"{APP_NAME} cannot process repositories that don't have an 'origin' remote",
            solution=(
                "Repositories cloned via git clone should always have one.\n"
                "Otherwise, please `git remote add origin` with a url that reflects the origin."
            ),
        )

    url = _canonicalize_origin_url(origin.url)
    commit_id = repo.head.commit.hexsha
    return RepoID(url, commit_id)


def _canonicalize_origin_url(url: str) -> str:
    if "://" in url:
        parsed: ParseResult = urlparse(url)
        cleaned_netloc = parsed.netloc.replace(
            f"{parsed.username}:{parsed.password}@",
            "",
        )
        return parsed._replace(netloc=cleaned_netloc).geturl()
    # scp-style is "only recognized if there are no slashes before the first colon"
    elif re.match("^[^/]*:", url):
        parts = url.split("@", 1)
        # replace the ':' in the host:path part with a '/'
        # and strip leading '/' from the path, if any
        parts[-1] = re.sub(r":/*", "/", parts[-1], count=1)
        return "ssh://" + "@".join(parts)
    else:
        raise UnsupportedFeature(
            f"Could not canonicalize repository origin url: {url}", solution=None
        )


def clone_as_tarball(url: str, ref: str, to_path: Path) -> None:
    """Clone a git repository, check out the specified revision and create a compressed tarball.

    The repository content will be under the app/ directory in the tarball.

    :param url: the URL of the repository
    :param ref: the revision to check out
    :param to_path: create the tarball at this path
    """
    list_url = [url]
    # Fallback to `https` if cloning source via ssh fails
    if "ssh://" in url:
        list_url.append(url.replace("ssh://", "https://"))

    with tempfile.TemporaryDirectory(prefix="cachito-") as temp_dir:
        for url in list_url:
            log.debug("Cloning the Git repository from %s", url)
            try:
                repo = Repo.clone_from(
                    url,
                    temp_dir,
                    no_checkout=True,
                    filter="blob:none",
                    # Don't allow git to prompt for a username if we don't have access
                    env={"GIT_TERMINAL_PROMPT": "0"},
                )
            except Exception as ex:
                log.warning(
                    "Failed cloning the Git repository from %s, ref: %s, exception: %s, exception-msg: %s",
                    url,
                    ref,
                    type(ex).__name__,
                    str(ex),
                )
                continue

            _reset_git_head(repo, ref)

            with tarfile.open(to_path, mode="w:gz") as archive:
                archive.add(repo.working_dir, "app")

            return

    raise FetchError("Failed cloning the Git repository")


def _reset_git_head(repo: Repo, ref: str) -> None:
    try:
        repo.head.reference = repo.commit(ref)  # type: ignore # 'reference' is a weird property
        repo.head.reset(index=True, working_tree=True)
    except Exception as ex:
        log.exception(
            "Failed on checking out the Git ref %s, exception: %s",
            ref,
            type(ex).__name__,
        )
        # Not necessarily a FetchError, but the checkout *does* also fetch stuff
        #   (because we clone with --filter=blob:none)
        raise FetchError(
            "Failed on checking out the Git repository. Please verify the supplied reference "
            f'of "{ref}" is valid.'
        )


def extract_git_info(vcs_url: str) -> dict[str, Any]:
    """
    Extract important info from a VCS requirement URL.

    Given a URL such as git+https://user:pass@host:port/namespace/repo.git@123456?foo=bar#egg=spam
    this function will extract:
    - the "clean" URL: https://user:pass@host:port/namespace/repo.git
    - the git ref: 123456
    - the host, namespace and repo: host:port, namespace, repo

    The clean URL and ref can be passed straight to scm.Git to fetch the repo.
    The host, namespace and repo will be used to construct the file path under deps/pip.

    :param str vcs_url: The URL of a VCS requirement, must be valid (have git ref in path)
    :return: Dict with url, ref, host, namespace and repo keys
    """
    # If scheme is git+protocol://, keep only protocol://
    # Do this before parsing URL, otherwise urllib may not extract URL params
    if vcs_url.startswith("git+"):
        vcs_url = vcs_url[len("git+") :]

    url = urlparse(vcs_url)

    ref = url.path[-40:]  # Take the last 40 characters (the git ref)
    clean_path = url.path[:-41]  # Drop the last 41 characters ('@' + git ref)

    # Note: despite starting with an underscore, the namedtuple._replace() method is public
    clean_url = url._replace(path=clean_path, params="", query="", fragment="")

    # Assume everything up to the last '@' is user:pass. This should be kept in the
    # clean URL used for fetching, but should not be considered part of the host.
    _, _, clean_netloc = url.netloc.rpartition("@")

    namespace_repo = clean_path.strip("/")
    if namespace_repo.endswith(".git"):
        namespace_repo = namespace_repo[: -len(".git")]

    # Everything up to the last '/' is namespace, the rest is repo
    namespace, _, repo = namespace_repo.rpartition("/")

    return {
        "url": clean_url.geturl(),
        "ref": ref.lower(),
        "host": clean_netloc,
        "namespace": namespace,
        "repo": repo,
    }
