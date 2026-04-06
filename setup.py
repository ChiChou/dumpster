import os
import shutil
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py

TOOLS = [
    ("decrypt", "unfairplay", "ent.xml"),
    ("wrapper", "dumpster", "ent.xml"),
]


class BuildIOS(build_py):
    """Compile iOS tools and stage them into ios_tools/ before packaging."""

    def run(self):
        for build_dir, binary, entxml in TOOLS:
            subprocess.run(["make", "-C", build_dir, "ios"], check=True)

            dest = os.path.join("ios_tools", build_dir)
            os.makedirs(dest, exist_ok=True)
            shutil.copy2(os.path.join(build_dir, binary), dest)
            shutil.copy2(os.path.join(build_dir, entxml), dest)

        super().run()


setup(cmdclass={"build_py": BuildIOS})
