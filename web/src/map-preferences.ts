const key = "aegis.hide-local-traffic";
export function hideLocalTraffic() {
  try {
    return localStorage.getItem(key) === "true";
  } catch {
    return false;
  }
}
export function saveHideLocalTraffic(value: boolean) {
  try {
    localStorage.setItem(key, String(value));
  } catch {
    /* View filters work even when browser storage is disabled. */
  }
}
