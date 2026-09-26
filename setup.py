import os
import shutil
import subprocess
import sys

if sys.platform not in {"darwin", "linux"}:
    raise RuntimeError("dumpster only supports macOS and Linux")

from setuptools import setup
from setuptools.command.build_py import build_py

TOOLS = [
    ("decrypt", "unfairplay", "ent.xml"),
    ("wrapper", "dumpster", "ent.xml"),
]


class BuildIOS(build_py):
    """Compile iOS tools and stage them into ios_tools/ before packaging."""

    def run(self):
        can_compile = sys.platform == "darwin" and all(
            os.path.isdir(build_dir) for build_dir, _, _ in TOOLS
        )
        for build_dir, binary, entxml in TOOLS:
            dest = os.path.join("ios_tools", build_dir)
            if can_compile:
                subprocess.run(["make", "-C", build_dir, "ios"], check=True)
                os.makedirs(dest, exist_ok=True)
                shutil.copy2(os.path.join(build_dir, binary), dest)
                shutil.copy2(os.path.join(build_dir, entxml), dest)

            for name in (binary, entxml):
                packaged = os.path.join(dest, name)
                if not os.path.isfile(packaged):
                    raise RuntimeError(
                        f"prebuilt iOS tool is missing: {packaged}; "
                        "build the package on macOS first"
                    )

        super().run()


setup(
    cmdclass={"build_py": BuildIOS},
    platforms=["macOS", "Linux"],
)
