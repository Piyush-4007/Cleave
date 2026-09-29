//! Cleave desktop shell.
//!
//! Starts the Python analysis engine (the PyInstaller-frozen backend shipped as a bundle
//! resource) on a free 127.0.0.1 port with a random per-launch token, then opens the
//! dashboard with that address and token injected as `window.__CLEAVE__`. The engine is
//! stopped when the app exits; if the app dies without exiting cleanly, the engine's own
//! parent-pid watchdog stops it (see backend/cleave/desktop.py).

// No console window behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::path::BaseDirectory;
use tauri::{Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

struct Engine(Mutex<Option<Child>>);

#[cfg(windows)]
const ENGINE_EXE: &str = "backend/backend.exe";
#[cfg(not(windows))]
const ENGINE_EXE: &str = "backend/backend";

/// Ask the OS for a free port. The listener is dropped before the engine binds it — a tiny
/// race another process would have to win on loopback, and the engine then fails loudly
/// (the dashboard shows "engine did not start") rather than talking to the wrong thing.
fn free_port() -> std::io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn start_engine(app: &tauri::App, port: u16, token: &str) -> Result<Child, Box<dyn std::error::Error>> {
    let exe = app.path().resolve(ENGINE_EXE, BaseDirectory::Resource)?;
    let data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    // Engine output goes to a log in the data dir: the first place to look if a scan fails.
    let log = File::create(data_dir.join("engine.log"))?;

    let mut cmd = Command::new(exe);
    cmd.arg("--port").arg(port.to_string())
        .arg("--data-dir").arg(&data_dir)
        .arg("--parent-pid").arg(std::process::id().to_string())
        // The token travels in the environment, never argv (process listings show argv).
        .env("CLEAVE_API_TOKEN", token)
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    if cfg!(debug_assertions) {
        // `tauri dev` serves the dashboard from Vite, a different origin than the bundle.
        cmd.env("CLEAVE_CORS_ORIGINS",
                 "http://localhost:3000,http://tauri.localhost,https://tauri.localhost,tauri://localhost");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    Ok(cmd.spawn()?)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let port = free_port()?;
            let token = uuid::Uuid::new_v4().simple().to_string();
            let child = start_engine(app, port, &token)?;
            app.manage(Engine(Mutex::new(Some(child))));

            let init = format!(
                "window.__CLEAVE__ = Object.freeze({{ apiBase: 'http://127.0.0.1:{port}', token: '{token}' }});"
            );
            WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                .title("Cleave")
                .inner_size(1360.0, 880.0)
                .min_inner_size(960.0, 640.0)
                .initialization_script(&init)
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Cleave app")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(mut child) = app.state::<Engine>().0.lock().unwrap().take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        });
}
