from __future__ import annotations
import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class CommandResult:
    tool: str
    command: list[str]
    returncode: int
    duration_seconds: float
    stdout_file: str
    stderr_file: str
    status: str
    note: str = ""

    def to_dict(self):
        return asdict(self)


def which_any(names: Iterable[str]) -> Optional[str]:
    for name in names:
        p = shutil.which(name)
        if p:
            return p
    return None


def run_command(tool: str, command: list[str], out_dir: Path, timeout: int = 1800, input_text: str | None = None) -> CommandResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{tool}.stdout.log"
    stderr_path = out_dir / f"{tool}.stderr.log"
    executable = shutil.which(command[0]) if "/" not in command[0] else command[0]
    if not executable or not Path(executable).exists():
        msg = f"missing executable: {command[0]}"
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(msg + "\n", encoding="utf-8")
        result = CommandResult(tool, command, 127, 0.0, str(stdout_path), str(stderr_path), "skipped", msg)
        (out_dir / f"{tool}.command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
        (out_dir / f"{tool}.run.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return result

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        duration = time.monotonic() - start
        stdout_path.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
        stderr_path.write_text(proc.stderr or "", encoding="utf-8", errors="replace")
        status = "ok" if proc.returncode == 0 else "error"
        result = CommandResult(tool, command, proc.returncode, round(duration, 3), str(stdout_path), str(stderr_path), status)
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        stdout_path.write_text((exc.stdout or "") if isinstance(exc.stdout, str) else "", encoding="utf-8", errors="replace")
        stderr_path.write_text(((exc.stderr or "") if isinstance(exc.stderr, str) else "") + "\nTIMEOUT\n", encoding="utf-8", errors="replace")
        result = CommandResult(tool, command, 124, round(duration, 3), str(stdout_path), str(stderr_path), "timeout", f"timeout after {timeout}s")

    (out_dir / f"{tool}.command.txt").write_text(shlex.join(command) + "\n", encoding="utf-8")
    (out_dir / f"{tool}.run.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return result
