"""Pre-built iOS tool binaries bundled at install time."""

import os

_HERE = os.path.dirname(__file__)


def get(build_dir: str, name: str) -> str:
    """Return the path to a bundled iOS binary or entitlements file."""
    path = os.path.join(_HERE, build_dir, name)
    if os.path.isfile(path):
        return path
    raise FileNotFoundError(
        f"{name} not found in ios_tools/{build_dir}/ — rebuild with: make -C {build_dir} ios"
    )
