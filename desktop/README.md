# Cleave desktop app

Cleave as a download-and-run Windows app: no Docker, no terminal, no Python install. A
[Tauri](https://tauri.app) window shows the dashboard. It talks to the analysis engine,
which is the Python backend frozen with PyInstaller and shipped inside the app.

```
Cleave.exe (Tauri, Rust)                     backend.exe (PyInstaller, Python)
  picks a free 127.0.0.1 port        ──►      FastAPI on 127.0.0.1:<port> only
  makes a random per-launch token    ──►      CLEAVE_API_TOKEN (env, never argv)
  injects window.__CLEAVE__          ◄──►     every call carries X-Cleave-Token
  stops the engine on exit                    exits by itself if the app dies (watchdog)
```

- **No Neo4j, Postgres or Redis.** The engine keeps the graph in memory and saves the
  last scan to `%APPDATA%\app.cleave.desktop\raw\`. The engine log is
  `%APPDATA%\app.cleave.desktop\engine.log`.
- **AWS access is unchanged and read-only.** "Connect with my AWS login" uses the
  machine's own AWS credentials. That includes `aws login` sessions, which the bundled
  boto3 reads directly. "Use a read-only role" assumes a role ARN you paste in. Cleave
  never stores a key.
- **Unsigned for now.** Windows SmartScreen shows "unknown publisher". Choose
  *More info → Run anyway*. Code signing is deferred on cost.

## Build (Windows)

Prerequisites: Rust (rustup), Node 20+, [uv](https://docs.astral.sh/uv/), and the Visual
Studio C++ Build Tools. WebView2 is already part of Windows 11.

```bash
cd desktop
uv venv --python 3.11 .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
npm install
npm run backend      # freeze the engine -> src-tauri/resources/backend/
npm run build        # builds frontend/dist, compiles the shell, makes the installer
```

The installer is written to
`src-tauri/target/release/bundle/nsis/Cleave_<version>_x64-setup.exe`. It installs
per-user, so no admin prompt.

`npm run dev` runs the shell against the Vite dev server. The engine must be frozen
first (`npm run backend`), because the shell launches the frozen build in dev too.

Rebuild the engine (`npm run backend`) after any change under `backend/`. The shell
bundles whatever is in `src-tauri/resources/backend/`.

## Other platforms

PyInstaller cannot cross-compile, so macOS and Linux builds need to run on those OSes
(for example a GitHub Actions matrix). The shell already chooses the right engine
binary name for each platform. Not done yet: Windows ships first.
