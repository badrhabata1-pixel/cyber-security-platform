// P5 Security Reports page.
// Loaded two ways from this one file: by the P4 shell (Vite) as a module page, and by ui/index.html
// when the service runs on its own. Written with createElement instead of JSX syntax so the
// browser can run it directly without a build step.
//
// Props: token    - the user's JWT (falls back to localStorage "token"); not needed with AUTH_DISABLED=true
//        apiBase  - where the P5 API lives; default VITE_REPORTS_API or http://127.0.0.1:8005
import { createElement as h, useCallback, useEffect, useRef, useState } from "react";

const SECTIONS = [
  ["summary", "Executive summary"],
  ["logs", "Log intelligence"],
  ["alerts", "Intrusion alerts"],
  ["domains", "Domain intelligence"],
  ["recommendations", "Recommended actions"],
];
const PRESETS = [["7 days", 7], ["30 days", 30], ["90 days", 90]];
const SOURCE_NAMES = { logs: "log analysis", alerts: "intrusion detection", domains: "domain intelligence" };
const DEFAULT_API = import.meta.env?.VITE_REPORTS_API ?? "http://127.0.0.1:8005";
const POLL_MS = 1500;

const STYLE = `
.p5r { --surface: #172435; --raised: #1d2d42; --border: #30445c; --text: #e7eef7; --muted: #93a4b8; --accent: #3987e5;
  --good: #0ca30c; --warning: #fab219; --critical: #e66767; color: var(--text); font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
.p5r * { box-sizing: border-box; }
.p5r h1 { font-size: 24px; margin: 0 0 4px; }
.p5r .lede { color: var(--muted); margin: 0 0 20px; }
.p5r .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 20px; }
.p5r .card h2 { font-size: 16px; margin: 0 0 14px; }
.p5r .row { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-end; }
.p5r label.field { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: var(--muted); }
.p5r input[type=date] { background: var(--raised); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font: inherit; color-scheme: dark; }
.p5r .presets { display: flex; gap: 6px; }
.p5r button { font: inherit; cursor: pointer; border-radius: 6px; }
.p5r button:focus-visible, .p5r input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.p5r .ghost { background: transparent; color: var(--text); border: 1px solid var(--border); padding: 7px 12px; }
.p5r .ghost:hover:not(:disabled) { background: var(--raised); }
.p5r .primary { background: var(--accent); color: #fff; border: 0; padding: 10px 18px; font-weight: 600; }
.p5r .primary:hover:not(:disabled) { filter: brightness(1.1); }
.p5r button:disabled { opacity: .55; cursor: not-allowed; }
.p5r fieldset { border: 0; padding: 0; margin: 18px 0; }
.p5r legend { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.p5r .checks { display: flex; flex-wrap: wrap; gap: 8px; }
.p5r .check { display: flex; align-items: center; gap: 8px; background: var(--raised); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; cursor: pointer; user-select: none; }
.p5r .check input { accent-color: var(--accent); margin: 0; }
.p5r .message { border-radius: 6px; padding: 10px 14px; margin-top: 14px; border: 1px solid var(--border); background: var(--raised); }
.p5r .message.error { border-color: var(--critical); }
.p5r .table-wrap { overflow-x: auto; }
.p5r table { width: 100%; border-collapse: collapse; font-size: 13px; min-width: 640px; }
.p5r th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px; padding: 0 10px 10px; border-bottom: 1px solid var(--border); }
.p5r td { padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.p5r .ref { font-weight: 600; font-variant-numeric: tabular-nums; }
.p5r .sub { display: block; color: var(--muted); font-size: 12px; }
.p5r .status { display: inline-flex; align-items: center; gap: 7px; font-weight: 600; }
.p5r .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
.p5r .spinner { width: 12px; height: 12px; border-radius: 50%; border: 2px solid var(--border); border-top-color: var(--accent); animation: p5r-spin .8s linear infinite; }
@keyframes p5r-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .p5r .spinner { animation: none; } }
.p5r .empty { color: var(--muted); text-align: center; padding: 28px 10px; }
`;

function useStyle() {
  useEffect(() => {
    if (document.getElementById("p5r-style")) return;
    const style = document.createElement("style");
    style.id = "p5r-style";
    style.textContent = STYLE;
    document.head.appendChild(style);
  }, []);
}

function isoDay(date) {
  return date.toISOString().slice(0, 10);
}

function daysAgo(days) {
  return isoDay(new Date(Date.now() - days * 86400000));
}

function storedToken() {
  try {
    return localStorage.getItem("token") || undefined;
  } catch {
    return undefined;
  }
}

function friendlyError(error) {
  if (error.status === 401) return "Your session has expired or is missing. Sign in again to manage reports.";
  if (error.status === 403) return "Your role cannot use reports. Only admins and analysts can generate and download them.";
  if (error.status) return error.message;
  return "The reporting service is unreachable. Check that it is running on port 8005.";
}

function formatDay(value) {
  return new Date(value).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
}

function formatTime(value) {
  return new Date(value).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

function StatusCell({ report }) {
  if (report.status === "processing") {
    return h("span", { className: "status" }, h("span", { className: "spinner", "aria-hidden": true }), "Generating");
  }
  if (report.status === "failed") {
    return h("span", null,
      h("span", { className: "status" }, h("span", { className: "dot", style: { background: "var(--critical)" } }), "Failed"),
      h("span", { className: "sub", title: report.error || "" }, "Generation failed, try again"));
  }
  const partial = report.unavailable && report.unavailable.length > 0;
  return h("span", null,
    h("span", { className: "status" }, h("span", { className: "dot", style: { background: partial ? "var(--warning)" : "var(--good)" } }), partial ? "Ready, partial data" : "Ready"),
    partial && h("span", { className: "sub" }, "Unavailable: " + report.unavailable.map((key) => SOURCE_NAMES[key] || key).join(", ")));
}

export default function ReportsPage({ token, apiBase } = {}) {
  useStyle();
  const base = apiBase ?? DEFAULT_API;
  const auth = token ?? storedToken();
  const [from, setFrom] = useState(() => daysAgo(7));
  const [to, setTo] = useState(() => isoDay(new Date()));
  const [sections, setSections] = useState(() => SECTIONS.map(([key]) => key));
  const [reports, setReports] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [downloading, setDownloading] = useState(null);
  const [message, setMessage] = useState(null);
  const pollRef = useRef(null);

  const request = useCallback(async (path, options = {}) => {
    const headers = { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(auth ? { Authorization: `Bearer ${auth}` } : {}) };
    const response = await fetch(base + path, { ...options, headers });
    if (!response.ok) {
      let detail = response.statusText;
      try {
        detail = (await response.json()).detail || detail;
      } catch {
        // not JSON: keep the status text
      }
      throw Object.assign(new Error(typeof detail === "string" ? detail : "Request failed"), { status: response.status });
    }
    return response;
  }, [base, auth]);

  const refresh = useCallback(async () => {
    try {
      const data = await (await request("/reports")).json();
      setReports(data.reports);
      setMessage((current) => (current && current.kind === "error" ? null : current));
    } catch (error) {
      setMessage({ kind: "error", text: friendlyError(error) });
    } finally {
      setLoaded(true);
    }
  }, [request]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Keep polling while any report is still being generated
  useEffect(() => {
    clearTimeout(pollRef.current);
    if (reports.some((report) => report.status === "processing")) pollRef.current = setTimeout(refresh, POLL_MS);
    return () => clearTimeout(pollRef.current);
  }, [reports, refresh]);

  const invalidRange = !from || !to || from > to;

  async function generate(event) {
    event.preventDefault();
    if (invalidRange || sections.length === 0) return;
    setSubmitting(true);
    setMessage(null);
    try {
      const created = await (await request("/reports", { method: "POST", body: JSON.stringify({ from, to, sections }) })).json();
      setMessage({ kind: "info", text: `Report ${created.reference} is being generated. It will be ready to download in a few seconds.` });
      await refresh();
    } catch (error) {
      setMessage({ kind: "error", text: friendlyError(error) });
    } finally {
      setSubmitting(false);
    }
  }

  async function download(report) {
    setDownloading(report.id);
    try {
      // A plain link cannot carry the bearer token, so fetch the PDF and hand it to the browser
      const blob = await (await request(report.download_url)).blob();
      const url = URL.createObjectURL(blob);
      const link = Object.assign(document.createElement("a"), { href: url, download: `${report.reference}.pdf` });
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setMessage({ kind: "error", text: friendlyError(error) });
    } finally {
      setDownloading(null);
    }
  }

  function toggle(key) {
    setSections((current) => (current.includes(key) ? current.filter((k) => k !== key) : SECTIONS.map(([k]) => k).filter((k) => k === key || current.includes(k))));
  }

  const form = h("form", { className: "card", onSubmit: generate },
    h("h2", null, "New report"),
    h("div", { className: "row" },
      h("label", { className: "field" }, "From", h("input", { type: "date", value: from, max: to || undefined, required: true, onChange: (e) => setFrom(e.target.value) })),
      h("label", { className: "field" }, "To", h("input", { type: "date", value: to, min: from || undefined, required: true, onChange: (e) => setTo(e.target.value) })),
      h("div", { className: "presets", role: "group", "aria-label": "Quick ranges" },
        PRESETS.map(([label, days]) => h("button", { key: label, type: "button", className: "ghost", onClick: () => { setFrom(daysAgo(days)); setTo(isoDay(new Date())); } }, label)))),
    h("fieldset", null,
      h("legend", null, "Sections to include"),
      h("div", { className: "checks" },
        SECTIONS.map(([key, label]) => h("label", { key, className: "check" },
          h("input", { type: "checkbox", checked: sections.includes(key), onChange: () => toggle(key) }), label)))),
    h("button", { type: "submit", className: "primary", disabled: submitting || invalidRange || sections.length === 0 },
      submitting ? "Starting…" : "Generate PDF report"),
    invalidRange && h("p", { className: "sub", style: { marginTop: 10 } }, "The start date must be on or before the end date."),
    message && h("div", { className: `message ${message.kind}`, role: message.kind === "error" ? "alert" : "status" }, message.text));

  const rows = reports.map((report) => h("tr", { key: report.id },
    h("td", null, h("span", { className: "ref" }, report.reference), h("span", { className: "sub" }, `${report.sections.length} of ${SECTIONS.length} sections`)),
    h("td", null, `${formatDay(report.date_from)} – ${formatDay(report.date_to)}`),
    h("td", null, report.requested_by),
    h("td", null, formatTime(report.created_at)),
    h("td", null, h(StatusCell, { report })),
    h("td", { style: { textAlign: "right" } },
      report.download_url && h("button", { type: "button", className: "ghost", disabled: downloading === report.id, onClick: () => download(report) },
        downloading === report.id ? "Downloading…" : "Download PDF"))));

  const history = h("section", { className: "card", "aria-labelledby": "p5r-history" },
    h("h2", { id: "p5r-history" }, "Report history"),
    h("div", { className: "table-wrap" },
      h("table", null,
        h("thead", null, h("tr", null, ["Reference", "Period", "Requested by", "Created", "Status", ""].map((title, i) => h("th", { key: i, scope: "col" }, title)))),
        h("tbody", null, rows.length ? rows : h("tr", null, h("td", { colSpan: 6, className: "empty" }, loaded ? "No reports yet. Generate the first one above." : "Loading reports…"))))));

  return h("div", { className: "p5r" },
    h("h1", null, "Security Reports"),
    h("p", { className: "lede" }, "Executive PDF reports that combine log analysis, intrusion alerts and domain intelligence for a chosen period."),
    form,
    history);
}
