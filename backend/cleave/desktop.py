"""Desktop entry point — the backend the Tauri app launches (PyInstaller-frozen).

    cleave-backend --port 51234 --data-dir <app data dir> [--parent-pid N]
    (token via the CLEAVE_API_TOKEN environment variable, never argv)

Same API as the compose stack, set up for one user on one machine:
  * binds 127.0.0.1 only — nothing on the network can reach it;
  * graph store is in-memory (no Neo4j); scans persist as the raw dump in the data dir;
  * the token comes through the environment, not the command line, where any local
    process listing could read it;
  * with --parent-pid, exits when the app does, even if the app crashed and never got to
    stop it — an orphaned backend holding AWS credentials is exactly what we don't want.
"""
from __future__ import annotations
import argparse
import os
import pathlib
import sys
import threading


def _exit_with_parent(pid: int) -> None:
    """Block until process `pid` exits, then exit this one."""
    def watch():
        if sys.platform == "win32":
            import ctypes
            SYNCHRONIZE, INFINITE = 0x00100000, 0xFFFFFFFF
            k32 = ctypes.windll.kernel32
            h = k32.OpenProcess(SYNCHRONIZE, False, pid)
            if h:
                k32.WaitForSingleObject(h, INFINITE)
                k32.CloseHandle(h)
        else:
            import time
            while True:
                try:
                    os.kill(pid, 0)  # signal 0 = existence probe on POSIX
                except OSError:
                    break
                time.sleep(2)
        os._exit(0)
    threading.Thread(target=watch, name="parent-watchdog", daemon=True).start()


def _load_env_file(path: pathlib.Path) -> None:
    """Load KEY=VALUE lines from a local settings file into the environment, without
    overriding anything already set. Blank lines and `#` comments are ignored; a value may
    be quoted. Best-effort: a missing or malformed file is simply skipped."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="cleave-backend")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--parent-pid", type=int)
    args = ap.parse_args(argv)

    raw = pathlib.Path(args.data_dir) / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    # Settings are read from the environment when cleave.config is first imported, so
    # set them before importing the app.
    os.environ["CLEAVE_OUTPUT_DIR"] = str(raw)
    os.environ["CLEAVE_GRAPH_STORE"] = "memory"
    os.environ.setdefault("CLEAVE_CORS_ORIGINS",
                          "http://tauri.localhost,https://tauri.localhost,tauri://localhost")
    # Optional local settings for opt-in features whose secrets must NOT pass through the
    # window — e.g. the teams PR flow's GitHub token. Put KEY=VALUE lines in
    # <data-dir>/settings.env; read here before the app imports its config. Never
    # overrides the values set above.
    _load_env_file(pathlib.Path(args.data_dir) / "settings.env")

    if args.parent_pid:
        _exit_with_parent(args.parent_pid)

    import uvicorn
    from cleave.api.main import app
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
