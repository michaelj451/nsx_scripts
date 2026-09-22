"""Unbuffered child output, written live to both the terminal and a log file."""
import codecs
from collections import deque
import os
from pathlib import Path
import subprocess
import sys


def stream_command(cmd: list, cwd: Path, log_path: Path) -> tuple[int, str]:
    env = dict(os.environ)
    env.setdefault("PYTHONPATH", str(cwd / "app"))
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tail = deque(maxlen=20)
    partial = ""
    with log_path.open("w", encoding="utf-8") as fh:
        with subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as proc:
            assert proc.stdout is not None
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            try:
                while chunk := proc.stdout.read1(8192):
                    output = decoder.decode(chunk)
                    fh.write(output)
                    fh.flush()
                    sys.stdout.write(output)
                    sys.stdout.flush()
                    lines = (partial + output).split("\n")
                    tail.extend(lines[:-1])
                    partial = lines[-1]
                output = decoder.decode(b"", final=True)
                fh.write(output)
                sys.stdout.write(output)
                sys.stdout.flush()
                if partial or output:
                    tail.append(partial + output)
                proc.wait()
            except BaseException:
                proc.kill()
                proc.wait()
                raise
    return proc.returncode, "\n".join(tail)
