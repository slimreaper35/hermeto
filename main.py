import os
from pathlib import Path

from hermeto.interface.cli import fetch_deps, generate_env, inject_files

PWD = Path(os.environ["PWD"])

SOURCE_DIR = PWD
OUTPUT_DIR = PWD.joinpath("hermeto-output")


def debug_fetch_deps():
    package_manager = "pip"
    fetch_deps(package_manager, SOURCE_DIR, OUTPUT_DIR)


def debug_generate_env():
    for_output_dir = Path("/tmp")
    output = Path("hermeto.env")
    generate_env(OUTPUT_DIR, for_output_dir, output)


def debug_inject_files():
    for_output_dir = Path("/tmp")
    inject_files(OUTPUT_DIR, for_output_dir)


def main():
    debug_fetch_deps()
    debug_generate_env()
    debug_inject_files()


if __name__ == "__main__":
    main()
