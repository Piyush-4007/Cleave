/*
  Resolve the newest Windows installer from the public releases repo, so "Get Cleave" always
  serves the current version without the site hardcoding it. Falls back to the releases page.
*/
const RELEASES_REPO = "Piyush-4007/Cleave";
export const RELEASES_PAGE = `https://github.com/${RELEASES_REPO}/releases/latest`;

export async function latestInstallerUrl(): Promise<string> {
  try {
    const r = await fetch(`https://api.github.com/repos/${RELEASES_REPO}/releases/latest`, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (r.ok) {
      const rel = await r.json();
      const exe = (rel.assets ?? []).find((a: { name?: string; browser_download_url?: string }) =>
        a.name?.toLowerCase().endsWith(".exe"),
      );
      if (exe?.browser_download_url) return exe.browser_download_url;
    }
  } catch {
    /* offline / rate-limited — fall through to the releases page */
  }
  return RELEASES_PAGE;
}

export function triggerDownload(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
