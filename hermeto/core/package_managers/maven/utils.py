from urllib.parse import urlparse

from hermeto.core.errors import PackageRejected

JAVA_TO_PYTHON_CHECKSUM_ALGORITHMS = {
    "SHA-256": "sha256",
    "SHA-1": "sha1",
    "SHA-512": "sha512",
    "SHA-224": "sha224",
    "SHA-384": "sha384",
    "MD5": "md5",
}


def convert_java_checksum_algorithm_to_python(java_algorithm: str) -> str:
    """Convert Java MessageDigest algorithm name to Python hashlib algorithm name."""
    python_algorithm = JAVA_TO_PYTHON_CHECKSUM_ALGORITHMS.get(java_algorithm)
    if not python_algorithm:
        raise PackageRejected(
            f"Unsupported checksum algorithm: {java_algorithm}",
            solution=f"Supported algorithms: {', '.join(JAVA_TO_PYTHON_CHECKSUM_ALGORITHMS.keys())}",
        )

    return python_algorithm


def derive_repository_id(url: str) -> str:
    """Derive a repository ID from a URL."""
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or "unknown"

    # Map common Maven repository hostnames to standard IDs
    hostname_to_id = {
        "repo1.maven.org": "central",
        "repo.maven.apache.org": "central",
        "central.maven.org": "central",
        "oss.sonatype.org": "sonatype",
        "s01.oss.sonatype.org": "sonatype",
        "repository.jboss.org": "jboss",
        "repo.spring.io": "spring",
    }

    return hostname_to_id.get(hostname, hostname)


def derive_pom_filename(artifact_id: str, version: str) -> str:
    """
    Derive the POM filename from artifact ID and version.

    Maven POM files don't have classifiers, so the format is always: `{artifact_id}-{version}.pom`
    """
    return f"{artifact_id}-{version}.pom"
