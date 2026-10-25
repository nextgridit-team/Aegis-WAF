const preference = matchMedia("(prefers-color-scheme: dark)");
let saved: string | null = null;
try {
  saved = localStorage.getItem("aegis-theme");
} catch {
  /* Storage may be disabled. */
}
function applyTheme(theme: string) {
  document.documentElement.dataset.theme = theme;
  document
    .querySelectorAll<HTMLButtonElement>('[data-action="toggle-theme"]')
    .forEach((button) => {
      button.textContent = theme === "dark" ? "Light mode" : "Dark mode";
      button.setAttribute("aria-pressed", String(theme === "dark"));
    });
}
applyTheme(
  saved === "light" || saved === "dark"
    ? saved
    : preference.matches
      ? "dark"
      : "light",
);
preference.addEventListener("change", (event) => {
  if (saved !== "light" && saved !== "dark")
    applyTheme(event.matches ? "dark" : "light");
});
export function toggleTheme() {
  saved = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("aegis-theme", saved);
  } catch {
    /* Keep the current session preference. */
  }
  applyTheme(saved);
}
export function themeControl() {
  const dark = document.documentElement.dataset.theme === "dark";
  return `<button type="button" data-action="toggle-theme" class="secondary compact theme-toggle" aria-label="Switch color theme" aria-pressed="${dark}">${dark ? "Light mode" : "Dark mode"}</button>`;
}
