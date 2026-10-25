import { esc } from "./ui";
export type ResponseStatus = {
  site_id: number;
  site_name: string | null;
  hostnames: string[];
  response_source: string;
  status: number;
  requests: number;
};
const sources: Record<string, string> = {
  upstream: "Upstream application",
  waf: "Aegis WAF",
  redirect: "Aegis HTTPS redirect",
  gateway_error: "Aegis gateway error",
  unknown: "Not recorded",
};
const statuses: Record<number, string> = {
  101: "Switching Protocols",
  200: "OK",
  201: "Created",
  202: "Accepted",
  204: "No Content",
  206: "Partial Content",
  301: "Moved Permanently",
  302: "Found",
  304: "Not Modified",
  307: "Temporary Redirect",
  308: "Permanent Redirect",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  408: "Request Timeout",
  409: "Conflict",
  413: "Content Too Large",
  415: "Unsupported Media Type",
  422: "Unprocessable Content",
  429: "Too Many Requests",
  500: "Internal Server Error",
  501: "Not Implemented",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};
export function responseSource(value?: string) {
  return sources[value || "unknown"] || "Not recorded";
}
export function responseStatusPanel(
  rows: ResponseStatus[],
  total: number,
  scope: string,
) {
  return `<section class="dashboard-panel"><h2>Response status</h2><p class="muted">${esc(scope)} · grouped by proxy host, response source and HTTP status. Share uses all completed requests in the selected application/time range.</p>${rows.length ? `<div class="table-wrap response-status-table" tabindex="0" role="region" aria-label="Response status breakdown"><table><thead><tr><th scope="col">Proxy host</th><th scope="col">Response source</th><th scope="col">HTTP status</th><th scope="col">Requests</th><th scope="col">Share of selected traffic</th></tr></thead><tbody>${rows.map((row) => `<tr><td>${esc(row.site_name || "Deleted proxy host · #" + row.site_id)}<small>${esc(row.hostnames.join(", ") || "Configured hostnames unavailable")}</small></td><td>${esc(responseSource(row.response_source))}</td><td><span class="badge ${row.status >= 500 ? "danger" : row.status >= 400 ? "warning" : "success"}">${row.status}${statuses[row.status] ? " " + esc(statuses[row.status]) : ""}</span></td><td>${row.requests.toLocaleString()}</td><td>${total ? ((row.requests / total) * 100).toLocaleString(undefined, { maximumFractionDigits: 1 }) : "0"}%</td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">Status codes appear as requests complete.</p>'}<p class="muted">Up to 100 most frequent groups. Host names and configured hostnames reflect current configuration. Older responses without recorded provenance show “Not recorded”; an upstream 403 or 502 is not automatically a WAF block.</p></section>`;
}

export function clientAddress(peer: string, objects?: string[]) {
  return objects?.length
    ? `<strong>${objects.map(esc).join(", ")}</strong><small>${esc(peer)} · current IP object match</small>`
    : esc(peer);
}
