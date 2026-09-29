import { Sun, MoonStars } from "@phosphor-icons/react";
import { useTheme } from "../theme";

export function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const next = theme === "dark" ? "Field manual (light)" : "Signal (dark)";
  return (
    <button
      onClick={toggle}
      aria-label={`Switch to ${next}`}
      title={`Switch to ${next}`}
      className="grid h-9 w-9 place-items-center rounded-md border border-[color:var(--line)]
                 text-[color:var(--muted)] transition-colors hover:text-[color:var(--text)]
                 hover:border-[color:var(--accent)] active:scale-[0.96]"
    >
      {theme === "dark" ? <Sun size={18} weight="regular" /> : <MoonStars size={18} weight="regular" />}
    </button>
  );
}
