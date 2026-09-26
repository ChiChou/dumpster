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
FRIDA_AGENT_DIR = "agent"
FRIDA_AGENT_SOURCE = os.path.join(FRIDA_AGENT_DIR, "installd.ts")
FRIDA_AGENT_DIST = os.path.join(FRIDA_AGENT_DIR, "dist", "installd.js")
FRIDA_COMPILER = os.path.join(
    FRIDA_AGENT_DIR,
    "node_modules",
    ".bin",
    "frida-compile.cmd" if os.name == "nt" else "frida-compile",
)
FRIDA_OBJC_BRIDGE = os.path.join(
    FRIDA_AGENT_DIR, "node_modules", "frida-objc-bridge"
)


class BuildPackage(build_py):
    """Build native iOS tools and the bundled Frida agent."""

    def run(self):
        if os.path.isfile(FRIDA_COMPILER) and os.path.isdir(FRIDA_OBJC_BRIDGE):
            os.makedirs(os.path.dirname(FRIDA_AGENT_DIST), exist_ok=True)
            subprocess.run(
                [
                    FRIDA_COMPILER,
                    FRIDA_AGENT_SOURCE,
                    "-o",
                    FRIDA_AGENT_DIST,
                    "-S",
                    "-c",
                ],
                check=True,
            )
        if not os.path.isfile(FRIDA_AGENT_DIST):
            raise RuntimeError(
                "prebuilt Frida agent is missing; run npm install and npm run build "
                "in agent/"
            )

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

        packaged_agent = os.path.join(self.build_lib, "dumpster", "installd.js")
        os.makedirs(os.path.dirname(packaged_agent), exist_ok=True)
        shutil.copy2(FRIDA_AGENT_DIST, packaged_agent)


setup(
    cmdclass={"build_py": BuildPackage},
    platforms=["macOS", "Linux"],
)
