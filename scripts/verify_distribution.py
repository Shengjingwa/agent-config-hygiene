from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path

REQUIRED_COMMON_SUFFIXES = (
    "agent_config_hygiene/fs_safety.py",
    "agent_config_hygiene/resources/skill/agent-config-hygiene/SKILL.md",
)
REQUIRED_WHEEL_SUFFIXES = (
    "share/agent-config-hygiene/schemas/report-v1.schema.json",
    "share/agent-config-hygiene/docs/PRIVACY.md",
    "share/agent-config-hygiene/docs/SECURITY.md",
)


def _assert_contents(
    names: list[str],
    artifact: Path,
    required_suffixes: tuple[str, ...],
) -> None:
    normalized = [name.replace("\\", "/") for name in names]
    for suffix in (*REQUIRED_COMMON_SUFFIXES, *required_suffixes):
        if not any(name.endswith(suffix) for name in normalized):
            raise RuntimeError(f"{artifact.name} is missing {suffix}")


def _venv_python(root: Path) -> Path:
    if sys.platform == "win32":
        return root / "Scripts" / "python.exe"
    return root / "bin" / "python"


def main() -> int:
    dist = Path("dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("Expected exactly one wheel and one source distribution")

    with zipfile.ZipFile(wheels[0]) as archive:
        _assert_contents(
            archive.namelist(),
            wheels[0],
            REQUIRED_WHEEL_SUFFIXES,
        )
    with tarfile.open(sdists[0], "r:gz") as archive:
        _assert_contents(
            archive.getnames(),
            sdists[0],
            (
                "schemas/report-v1.schema.json",
                "PRIVACY.md",
                "SECURITY.md",
            ),
        )

    with tempfile.TemporaryDirectory() as directory:
        temporary_root = Path(directory)
        environment = temporary_root / "venv"
        probe_root = temporary_root / "probe"
        probe_root.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment)
        python = _venv_python(environment)
        clean_environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() not in {"PYTHONHOME", "PYTHONPATH"}
        }
        clean_environment["PYTHONNOUSERSITE"] = "1"
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--force-reinstall",
                str(wheels[0].resolve()),
            ],
            check=True,
            cwd=probe_root,
            env=clean_environment,
        )
        subprocess.run(
            [
                str(python),
                "-c",
                (
                    "import agent_config_hygiene, sys; "
                    "from pathlib import Path; "
                    "from agent_config_hygiene.scheduling import scheduled_command; "
                    "module = Path(agent_config_hygiene.__file__).resolve(); "
                    "prefix = Path(sys.prefix).resolve(); "
                    "assert module.is_relative_to(prefix), (module, prefix); "
                    "command = scheduled_command(Path.cwd() / 'state'); "
                    "assert command[0] == sys.executable, (command[0], sys.executable)"
                ),
            ],
            check=True,
            cwd=probe_root,
            env=clean_environment,
        )
        subprocess.run(
            [
                str(python),
                "-m",
                "agent_config_hygiene",
                "doctor",
            ],
            check=True,
            cwd=probe_root,
            env=clean_environment,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
