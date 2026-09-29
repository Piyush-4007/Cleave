/*
  Desktop mode. The Tauri shell injects `window.__CLEAVE__` before the page loads with the
  local backend's address and its per-launch token. Absent => the web build (dev server or
  hosted landing), which keeps today's behaviour.
*/
export interface DesktopConfig {
  apiBase: string; // e.g. http://127.0.0.1:51234
  token: string; // sent as X-Cleave-Token on every call
}

export const DESKTOP: DesktopConfig | undefined = (window as unknown as { __CLEAVE__?: DesktopConfig })
  .__CLEAVE__;
