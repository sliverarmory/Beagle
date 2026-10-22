"""Beagle-owned angreal task for compiling the verified upstream snapshot."""
import json
import os
import pathlib
import shlex
import subprocess

import angreal


@angreal.command(name="beagle-static", about="Build the static Beagle backend")
def beagle_static():
    root = pathlib.Path(angreal.get_root()).parent
    arguments = [
        "make", "-f", "Makefile.beagle",
        "BEAGLE_CC=" + shlex.join(json.loads(os.environ["BEAGLE_CC"])),
        "BEAGLE_AR=" + shlex.join(json.loads(os.environ["BEAGLE_AR"])),
        "BEAGLE_SQLITE_INCLUDE=" + os.environ["BEAGLE_SQLITE_INCLUDE"],
    ]
    for name in ("BISON", "FLEX"):
        if os.environ.get(name):
            arguments.append(name + "=" + os.environ[name])
    # The upstream multi-output rules predate grouped targets. Generate each pair
    # before parallel compilation so make cannot run Bison/Flex twice in a race.
    for target in ("build/parser/cypher_gram.tab.c", "build/parser/cypher_scanner.c"):
        subprocess.run(arguments + [target], cwd=root, check=True)
    jobs = max(1, int(os.environ.get("BEAGLE_BUILD_JOBS", "1")))
    subprocess.run(arguments + ["-j", str(jobs), "beagle-static"], cwd=root, check=True)
