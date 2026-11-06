"""Bounded, mandatory evidence for the existing readiness transport."""
import datetime
import itertools
import os
import json
import re
import subprocess
import time

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
LIMIT = 16384
_sequence = itertools.count(1)
retained_owners = []

def owned_query(command, capture_output=True, timeout=6):
    """A reporting deadline never terminates an owned transport process."""
    from windows_powershell import environment
    owner = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=environment(command[0]))
    retained_owners.append(owner)
    stdout, stderr = owner.communicate(timeout=timeout)
    retained_owners.remove(owner)
    return subprocess.CompletedProcess(command, owner.returncode, stdout, stderr)
_ASSIGNMENT = re.compile(
    r"""(?ix)(\b[\w.-]*(?:credential|password|token)[\w.-]*["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\r\n]+)"""
)

def readiness_command(here, nonce):
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("Invalid readiness nonce")
    return [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
            "Bypass", "-File", str(here / "guest-read.ps1"), "-Mode", "ready",
            "-Nonce", nonce]

def bounded(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8-sig", errors="replace")
    text = _ASSIGNMENT.sub(r"\1[REDACTED]", value or "")
    encoded = text.encode("utf-8")
    return encoded[:LIMIT].decode("utf-8", errors="ignore"), len(encoded) > LIMIT

def query(here, nonce, out, runner=None):
    command = readiness_command(here, nonce)
    sequence = next(_sequence)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock = time.monotonic()
    result = None
    error = None
    try:
        result = (runner or owned_query)(command, capture_output=True, timeout=6)
        if result.returncode:
            raise RuntimeError("Producer readiness query failed")
        return json.loads(result.stdout.decode("utf-8-sig"))
    except BaseException as exc:
        error = exc
        raise
    finally:
        # Never serialize exception args, subprocess args, or environment mappings.
        try:
            stdout, stdout_cut = bounded(getattr(result, "stdout", None) if result is not None else getattr(error, "stdout", None))
            stderr, stderr_cut = bounded(getattr(result, "stderr", None) if result is not None else getattr(error, "stderr", None))
            record = dict(schema=2, sequence=sequence, command=command,
                utcStart=start, utcEnd=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                elapsedSeconds=time.monotonic()-clock,
                returncode=getattr(result, "returncode", None),
                stdout=stdout, stderr=stderr, stdoutTruncated=stdout_cut,
                stderrTruncated=stderr_cut,
                errorClassification=("timeout" if isinstance(error, subprocess.TimeoutExpired)
                    else "subprocess-nonzero-exit" if result is not None and result.returncode
                    else type(error).__name__ if error is not None else None),
                timeoutSeconds=6 if isinstance(error, subprocess.TimeoutExpired) else None)
            with (out / ("producer-readiness-%06d.json" % sequence)).open("x", encoding="utf-8") as stream:
                json.dump(record, stream, ensure_ascii=True)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception as persistence_error:
            if error is None:
                raise RuntimeError("Readiness diagnostics persistence failed") from persistence_error
            if hasattr(error, "add_note"):
                error.add_note("Readiness diagnostics persistence failed")
