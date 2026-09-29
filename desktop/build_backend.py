"""Freeze the backend into desktop/src-tauri/resources/backend/ (PyInstaller, one-dir).

    desktop/.venv/Scripts/python build_backend.py

One-dir, not one-file: one-file unpacks all of botocore's service data to a temp folder
on every launch, which costs seconds of startup. The Tauri app ships the folder as a
resource and launches cleave-backend(.exe) from it.
"""
import pathlib
import shutil
import sys
import PyInstaller.__main__

HERE = pathlib.Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend"
OUT = HERE / "src-tauri" / "resources"
WORK = HERE / "build"
# --collect-* resolve `cleave` in THIS process, so it must be importable here too.
sys.path.insert(0, str(BACKEND))

shutil.rmtree(OUT / "backend", ignore_errors=True)
PyInstaller.__main__.run([
    str(HERE / "backend_entry.py"),
    "--name", "backend",           # -> resources/backend/backend(.exe)
    "--onedir", "--noconfirm", "--clean", "--console",
    "--distpath", str(OUT), "--workpath", str(WORK), "--specpath", str(WORK),
    "--paths", str(BACKEND),
    "--collect-submodules", "cleave",     # collectors register themselves on import
    "--collect-submodules", "uvicorn",    # uvicorn picks loops/protocols by string name
    "--collect-data", "cleave",           # paths/policy.json (weights, remediation costs)
    "--collect-all", "awscrt",            # native extension behind `aws login` creds
    "--exclude-module", "neo4j",
    "--exclude-module", "tkinter",
    "--exclude-module", "pytest",
])
print("built ->", OUT / "backend")
