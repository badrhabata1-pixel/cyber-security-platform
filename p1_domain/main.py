from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from scanners.blacklist_check import get_blacklist_info
from scanners.dns_check import get_dns_info
from scanners.heuristics_check import analyze_heuristics
from scanners.risk_score import calculate_risk
from scanners.ssl_check import get_ssl_info
from scanners.whois_check import get_whois_info

app = FastAPI(title="Domain & URL Checker API", version="1.0")


class ScanRequest(BaseModel):
    domain: str


def normalize_domain(value: str) -> str:
    # المستخدم ممكن يكتب URL كامل (https://www.google.com/path) فبناخد اسم الدومين بس
    value = value.strip()
    host = urlparse(value if "://" in value else f"//{value}").hostname or ""
    return host.removeprefix("www.")


# دي القاعدة الثابتة اللي اتفقنا عليها إن كل خدمة لازم يكون فيها /health
@app.get("/health")
def health_check():
    return {"status": "ok"}


# الفحوصات الخمسة (WHOIS / DNS / SSL / Blacklist / Heuristics) وبعدها محرك التقييم بيحسب risk_score و risk_level و reasons
@app.post("/scan")
def scan_domain(payload: ScanRequest):
    domain = normalize_domain(payload.domain)

    # الفحوصات مستقلة عن بعض، فبنشغلهم بالتوازي: الوقت الكلي = وقت أبطأ فحص بس
    # (كل scanner مصمم إنه ميرميش exception، فالـ result() آمنة)
    with ThreadPoolExecutor(max_workers=5) as pool:
        whois_job = pool.submit(get_whois_info, domain)
        dns_job = pool.submit(get_dns_info, domain)
        ssl_job = pool.submit(get_ssl_info, domain)
        blacklist_job = pool.submit(get_blacklist_info, domain)
        # الـ heuristics بتاخد اللي المستخدم كتبه بالظبط: الـ @ والطول والـ path بيضيعوا بعد استخراج الدومين
        heuristics_job = pool.submit(analyze_heuristics, payload.domain)

    whois_data = whois_job.result()
    dns_data = dns_job.result()
    ssl_data = ssl_job.result()
    blacklist_data = blacklist_job.result()

    # محرك التقييم بيجمع نتايج الفحوصات الخمسة في درجة واحدة (0-100) ومستوى خطر وأسباب مرتبة من الأخطر للأقل
    risk_score, risk_level, reasons = calculate_risk(
        whois_data, dns_data, ssl_data, blacklist_data, heuristics_job.result()
    )

    return {
        "id": 1,
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "whois": whois_data,
        "dns": dns_data,
        "ssl": ssl_data,
        "blacklist": blacklist_data,
        "reasons": reasons
    }


# واجهة اختبار مؤقتة من المتصفح، مش جزء من العقد
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def test_ui():
    return TEST_UI_HTML


TEST_UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Domain Recon &middot; SVC-01</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --ink: #05070a;
      --panel: #0a0e13;
      --line: #17202a;
      --line-strong: #263241;
      --text: #d4dee8;
      --muted: #66768a;
      --ok: #3cffd0;
      --warn: #ffab2e;
      --err: #ff4d5e;
      --high: #ff6b3d;
      --crit: #ff2e63;
    }
    body { background: var(--ink); color: var(--text); font-family: "JetBrains Mono", ui-monospace, monospace; }
    .font-display { font-family: "Chakra Petch", "JetBrains Mono", sans-serif; }
    .text-muted { color: var(--muted); }
    .text-ok { color: var(--ok); }

    [data-tone="ok"]    { --tone: var(--ok); }
    [data-tone="warn"]  { --tone: var(--warn); }
    [data-tone="err"]   { --tone: var(--err); }
    [data-tone="muted"] { --tone: var(--muted); }
    [data-tone="high"]  { --tone: var(--high); }
    [data-tone="crit"]  { --tone: var(--crit); }

    /* Atmosphere: blueprint grid fading from the top, soft glow, faint CRT scanlines */
    .bg-grid {
      position: fixed; inset: 0; z-index: -2; pointer-events: none; opacity: .6;
      background-image: linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px);
      background-size: 44px 44px;
      -webkit-mask-image: radial-gradient(ellipse 90% 70% at 50% 0%, #000 25%, transparent 75%);
      mask-image: radial-gradient(ellipse 90% 70% at 50% 0%, #000 25%, transparent 75%);
    }
    .bg-glow {
      position: fixed; top: -30vh; left: 50%; width: 90vw; height: 70vh; transform: translateX(-50%);
      z-index: -1; pointer-events: none;
      background: radial-gradient(closest-side, rgba(60, 255, 208, .10), transparent);
    }
    .scanlines {
      position: fixed; inset: 0; z-index: 60; pointer-events: none;
      background: repeating-linear-gradient(0deg, rgba(255, 255, 255, .016) 0 1px, transparent 1px 3px);
    }

    /* Panels with HUD corner brackets */
    .panel { position: relative; background: linear-gradient(180deg, rgba(13, 18, 25, .92), rgba(7, 10, 14, .92)); border: 1px solid var(--line); }
    .panel::before, .panel::after { content: ""; position: absolute; width: 14px; height: 14px; pointer-events: none; }
    .panel::before { top: -1px; left: -1px; border-top: 1px solid var(--ok); border-left: 1px solid var(--ok); }
    .panel::after { bottom: -1px; right: -1px; border-bottom: 1px solid var(--ok); border-right: 1px solid var(--ok); }
    #scan-form { transition: border-color .2s, box-shadow .2s; }
    #scan-form:focus-within { border-color: rgba(60, 255, 208, .35); box-shadow: 0 0 0 4px rgba(60, 255, 208, .06), 0 24px 60px -32px rgba(60, 255, 208, .45); }

    .label { font-size: 10.5px; letter-spacing: .22em; text-transform: uppercase; color: var(--muted); }
    .eyebrow { font-size: 11px; letter-spacing: .28em; text-transform: uppercase; color: var(--ok); }
    .caret { color: var(--ok); animation: blink 1.1s steps(1) infinite; }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); animation: ping 2.2s ease-out infinite; }

    /* Command-line target input */
    .prompt { color: var(--ok); font-weight: 700; white-space: nowrap; }
    .console-input { color: #fff; caret-color: var(--ok); font-size: 15px; }
    .console-input::placeholder { color: #3d4a59; }
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 10px; min-height: 56px; padding: 0 26px;
      font-family: "Chakra Petch", sans-serif; font-weight: 700; font-size: 13px; letter-spacing: .18em; text-transform: uppercase;
      color: var(--ink); background: var(--ok); transition: background .2s, box-shadow .2s;
    }
    .btn:hover:not(:disabled) { background: #8dffe4; box-shadow: 0 0 28px rgba(60, 255, 208, .35); }
    .btn:focus-visible { outline: 2px solid var(--ink); outline-offset: -5px; }
    .btn:disabled { cursor: wait; background: #1d6b59; color: #c9fff0; }
    .spinner { display: none; width: 14px; height: 14px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: spin .7s linear infinite; }
    .is-loading .spinner { display: inline-block; }
    .scanbar { position: relative; height: 2px; overflow: hidden; }
    .scanbar::after {
      content: ""; position: absolute; top: 0; bottom: 0; left: 0; width: 35%; opacity: 0; transform: translateX(-100%);
      background: linear-gradient(90deg, transparent, var(--ok), transparent);
    }
    .is-loading .scanbar::after { opacity: 1; animation: sweep 1.1s ease-in-out infinite; }

    .alert { border: 1px solid rgba(255, 77, 94, .45); border-left-width: 3px; color: #ffb3bb; background: linear-gradient(90deg, rgba(255, 77, 94, .14), rgba(255, 77, 94, .03)); }

    /* Result dossier */
    .badge {
      display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; white-space: nowrap;
      font-size: 11px; letter-spacing: .2em; text-transform: uppercase;
      color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 45%, transparent); background: color-mix(in srgb, var(--tone) 8%, transparent);
    }
    .badge::before { content: ""; width: 6px; height: 6px; background: currentColor; box-shadow: 0 0 10px currentColor; }
    .cell { background: var(--panel); padding: 18px 20px; }
    .cell-value { margin-top: 8px; font-size: 18px; font-weight: 500; color: #fff; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
    .cell-value.is-small { font-size: 15px; }
    .cell-sub { margin-top: 4px; min-height: 1.2em; font-size: 11px; color: var(--muted); }
    /* .flag cells light up by status: mint edge when fine, glowing frame when warn/err */
    .flag .cell-value { color: var(--tone, #fff); }
    .flag[data-tone="ok"] { box-shadow: inset 2px 0 0 var(--ok); }
    .flag[data-tone="warn"], .flag[data-tone="err"] {
      box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--tone) 55%, transparent), inset 0 0 40px color-mix(in srgb, var(--tone) 14%, transparent);
    }
    .flag[data-tone="warn"] .cell-value, .flag[data-tone="err"] .cell-value { animation: alarm 1.6s ease-in-out infinite; }
    .flag[data-tone="warn"] .cell-sub, .flag[data-tone="err"] .cell-sub { color: var(--tone); }

    /* DNS record rows */
    .rec-key { font-family: "Chakra Petch", sans-serif; font-size: 22px; font-weight: 700; line-height: 1; color: #fff; }
    .rec-count { margin-left: 6px; font-family: "JetBrains Mono", monospace; font-size: 11px; font-weight: 400; color: var(--ok); vertical-align: top; }
    .chips { display: flex; flex-wrap: wrap; align-content: flex-start; gap: 6px; }
    .chip { padding: 4px 9px; font-size: 12px; color: var(--text); border: 1px solid var(--line-strong); background: rgba(255, 255, 255, .02); overflow-wrap: anywhere; }
    .chip.is-empty { color: var(--muted); border-style: dashed; }
    .rec-title { font-family: "Chakra Petch", sans-serif; font-size: 16px; font-weight: 700; color: #fff; }
    .rec-sub { margin-top: 4px; font-size: 11.5px; line-height: 1.5; color: var(--muted); }
    .rec-tech { display: inline-block; margin-top: 8px; padding: 1px 6px; font-size: 9.5px; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); border: 1px solid var(--line-strong); }
    .protects { font-size: 13px; line-height: 1.6; color: var(--text); }
    .protects span { margin-right: 6px; font-size: 10px; letter-spacing: .2em; text-transform: uppercase; color: var(--ok); }

    /* Plain-language email verdict */
    .verdict {
      display: flex; align-items: flex-start; gap: 16px; margin: 20px; padding: 16px 18px;
      border: 1px solid color-mix(in srgb, var(--tone) 40%, transparent); border-left: 3px solid var(--tone);
      background: linear-gradient(90deg, color-mix(in srgb, var(--tone) 14%, transparent), color-mix(in srgb, var(--tone) 3%, transparent));
    }
    .verdict-icon {
      flex: none; display: grid; place-items: center; width: 44px; height: 44px; font-size: 22px;
      border: 1px solid color-mix(in srgb, var(--tone) 45%, transparent); background: color-mix(in srgb, var(--tone) 10%, transparent);
    }
    .verdict[data-tone="err"] .verdict-icon { animation: alarm-box 1.8s ease-in-out infinite; }
    .verdict-title { font-family: "Chakra Petch", sans-serif; font-size: 18px; font-weight: 700; letter-spacing: .02em; color: var(--tone); }

    /* "?" helper tooltips: hover on desktop, tap/focus on touch and keyboard */
    .tip { position: relative; display: inline-flex; }
    .tip-btn {
      display: inline-grid; place-items: center; width: 18px; height: 18px; border-radius: 50%; cursor: help;
      font-size: 11px; line-height: 1; color: var(--muted); border: 1px solid var(--line-strong); transition: color .15s, border-color .15s;
    }
    .tip-btn:hover, .tip-btn:focus-visible { color: var(--ok); border-color: var(--ok); outline: none; }
    .tip-body {
      position: absolute; left: -8px; bottom: calc(100% + 10px); z-index: 30; width: min(280px, 78vw); padding: 10px 12px;
      font-size: 12px; line-height: 1.55; color: var(--text); background: #0f151c; border: 1px solid var(--line-strong); box-shadow: 0 14px 34px rgba(0, 0, 0, .55);
      opacity: 0; visibility: hidden; pointer-events: none; transform: translateY(4px); transition: opacity .15s, transform .15s, visibility .15s;
    }
    .tip-body b { color: #fff; font-weight: 500; }
    .tip-body code { color: var(--ok); }
    .tip:hover .tip-body, .tip:focus-within .tip-body { opacity: 1; visibility: visible; transform: none; }

    /* SSL verification checklist: pass / fail / not checked */
    .check { display: flex; align-items: center; gap: 12px; padding: 13px 20px; background: var(--panel); font-size: 12.5px; color: var(--text); }
    .check[data-tone="muted"] { color: var(--muted); }
    .check-mark {
      flex: none; display: grid; place-items: center; width: 20px; height: 20px; font-size: 12px; font-weight: 700;
      color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 50%, transparent); background: color-mix(in srgb, var(--tone) 10%, transparent);
    }

    /* Threat-intel card: big detection count, report link, 0 / 1-2 / 3+ detection scale */
    .cell-value.is-big { font-family: "Chakra Petch", sans-serif; font-size: 34px; font-weight: 700; line-height: 1.1; }
    .vt-link { display: inline-block; margin-top: 8px; font-size: 15px; color: var(--ok); }
    .vt-link:hover { text-decoration: underline; }
    .scale-seg {
      padding: 8px 10px; font-size: 11px; color: var(--muted); background: rgba(255, 255, 255, .015);
      border-top: 3px solid color-mix(in srgb, var(--tone) 22%, transparent); transition: background .3s, border-color .3s, color .3s;
    }
    .scale-seg span { display: block; font-family: "Chakra Petch", sans-serif; font-size: 15px; font-weight: 700; color: color-mix(in srgb, var(--tone) 40%, var(--muted)); }
    .scale-seg[data-active="true"] { color: var(--text); border-top-color: var(--tone); background: color-mix(in srgb, var(--tone) 10%, transparent); }
    .scale-seg[data-active="true"] span { color: var(--tone); }

    /* Recommended action box and flagged-vendor chips */
    .action { margin: 0 20px 20px; padding: 16px 18px; border: 1px solid color-mix(in srgb, var(--tone) 35%, var(--line)); background: rgba(255, 255, 255, .02); }
    .action .label { color: var(--tone); }
    .action-icon { flex: none; font-size: 20px; line-height: 1.35; }
    .action-head { font-family: "Chakra Petch", sans-serif; font-weight: 700; letter-spacing: .02em; color: var(--tone); }
    .action-steps li { position: relative; margin-top: 6px; padding-left: 18px; font-size: 12.5px; line-height: 1.55; color: var(--muted); }
    .action-steps li::before { content: "→"; position: absolute; left: 0; color: var(--tone); }
    #t-vendors .chip:not(.is-empty) { color: var(--tone); border-color: color-mix(in srgb, var(--tone) 45%, transparent); background: color-mix(in srgb, var(--tone) 8%, transparent); }
    #t-vendors[data-tone="ok"] .chip.is-empty { color: var(--ok); border-style: solid; border-color: color-mix(in srgb, var(--ok) 35%, transparent); }

    /* Heuristic red flags: one row per finding with its plain-language explanation */
    .findings { display: grid; gap: 1px; background: var(--line); }
    .finding { display: flex; gap: 14px; padding: 16px 20px; background: var(--panel); box-shadow: inset 2px 0 0 var(--tone); animation: rise .45s ease-out both; }
    .finding-mark {
      flex: none; display: grid; place-items: center; width: 26px; height: 26px; font-family: "Chakra Petch", sans-serif; font-size: 13px; font-weight: 700;
      color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 50%, transparent); background: color-mix(in srgb, var(--tone) 10%, transparent);
    }
    .finding-title { font-family: "Chakra Petch", sans-serif; font-size: 15px; font-weight: 700; color: #fff; }
    .finding-detail { margin-top: 2px; font-size: 12px; color: var(--tone); overflow-wrap: anywhere; }
    .finding-why { margin-top: 8px; font-size: 12.5px; line-height: 1.6; color: var(--text); }
    .finding-why span { margin-right: 6px; font-size: 10px; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); }

    /* Threat score hero: 270° gauge split into the four risk zones, coloured by level */
    #risk { border-color: color-mix(in srgb, var(--tone) 40%, var(--line)); box-shadow: 0 30px 80px -50px var(--tone); }
    #risk::before, #risk::after { border-color: var(--tone); }
    #risk[data-tone="crit"] { animation: rise .7s cubic-bezier(.2, .7, .2, 1) forwards, crit-glow 2.4s ease-in-out .7s infinite; }
    .gauge { position: relative; width: 230px; max-width: 100%; margin: 0 auto; }
    .gauge svg { display: block; width: 100%; height: auto; overflow: visible; }
    .gauge circle { fill: none; stroke-width: 12; }
    .zone { stroke: var(--tone); opacity: .16; }
    .gauge-arc { stroke: var(--tone); transition: stroke-dasharray 1.2s cubic-bezier(.2, .7, .2, 1); filter: drop-shadow(0 0 6px color-mix(in srgb, var(--tone) 70%, transparent)); }
    .gauge-tick { stroke: var(--muted); stroke-width: 2; }
    .gauge-end { fill: var(--muted); font-size: 10px; font-family: "JetBrains Mono", monospace; }
    .gauge-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; padding-top: 4px; }
    .gauge-score {
      font-family: "Chakra Petch", sans-serif; font-size: 68px; font-weight: 700; line-height: 1; color: var(--tone);
      font-variant-numeric: tabular-nums; text-shadow: 0 0 26px color-mix(in srgb, var(--tone) 45%, transparent);
    }
    .gauge-max { margin-top: 2px; font-size: 12px; letter-spacing: .2em; color: var(--muted); }
    .gauge-level { margin-top: 12px; font-family: "Chakra Petch", sans-serif; font-size: 13px; font-weight: 700; letter-spacing: .3em; text-transform: uppercase; color: var(--tone); }
    .reason { display: flex; align-items: flex-start; gap: 10px; padding: 8px 0; border-bottom: 1px dashed var(--line); font-size: 13px; line-height: 1.5; color: var(--text); }
    .reason:last-child { border-bottom: 0; }
    .reason[data-kind="note"] { color: var(--muted); }
    .reason-mark {
      flex: none; display: grid; place-items: center; width: 18px; height: 18px; margin-top: 1px; font-size: 11px; font-weight: 700;
      color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 50%, transparent); background: color-mix(in srgb, var(--tone) 8%, transparent);
    }
    #risk-more summary { list-style: none; cursor: pointer; padding: 8px 0 2px; }
    #risk-more summary::-webkit-details-marker { display: none; }
    #risk-more summary:hover { color: var(--text); }
    @keyframes crit-glow { 50% { box-shadow: 0 30px 90px -36px var(--crit), 0 0 0 1px color-mix(in srgb, var(--crit) 45%, transparent); } }

    .life-track { position: relative; height: 8px; background: repeating-linear-gradient(90deg, var(--line-strong) 0 2px, transparent 2px 9px); }
    .life-fill {
      position: absolute; top: 0; bottom: 0; left: 0; width: 0; transition: width 1.1s cubic-bezier(.2, .7, .2, 1);
      background: linear-gradient(90deg, color-mix(in srgb, var(--tone) 10%, transparent), var(--tone));
      box-shadow: 0 0 16px color-mix(in srgb, var(--tone) 40%, transparent);
    }
    .life-marker { position: absolute; top: -7px; bottom: -7px; left: 0; width: 2px; margin-left: -1px; background: #fff; transition: left 1.1s cubic-bezier(.2, .7, .2, 1); }
    .life-marker span { position: absolute; bottom: calc(100% + 6px); left: 0; font-size: 9.5px; letter-spacing: .22em; color: #fff; white-space: nowrap; }

    details.raw summary { list-style: none; cursor: pointer; }
    details.raw summary::-webkit-details-marker { display: none; }
    details.raw summary::before { content: "+ "; color: var(--ok); }
    details.raw[open] summary::before { content: "- "; }
    details.raw summary:hover { color: var(--text); }

    .log li { display: grid; grid-template-columns: auto auto 1fr; gap: 12px; padding: 3px 0; animation: rise .35s ease-out; }
    .log .tag { color: var(--tone); }

    .reveal { opacity: 0; animation: rise .7s cubic-bezier(.2, .7, .2, 1) forwards; animation-delay: var(--d, 0ms); }
    @keyframes rise { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }
    @keyframes sweep { to { transform: translateX(300%); } }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes blink { 50% { opacity: 0; } }
    @keyframes ping { 0% { box-shadow: 0 0 0 0 rgba(60, 255, 208, .6); } 80%, 100% { box-shadow: 0 0 0 9px rgba(60, 255, 208, 0); } }
    @keyframes alarm { 50% { text-shadow: 0 0 16px var(--tone); } }
    @keyframes alarm-box { 50% { box-shadow: 0 0 22px color-mix(in srgb, var(--tone) 55%, transparent); } }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; transition: none !important; }
      .reveal { opacity: 1; }
    }
  </style>
</head>
<body class="min-h-screen antialiased">
  <div class="bg-grid"></div>
  <div class="bg-glow"></div>
  <div class="scanlines"></div>

  <header class="sticky top-0 z-40 border-b border-[var(--line)] bg-[#05070acc] backdrop-blur">
    <div class="mx-auto flex max-w-3xl items-center justify-between gap-4 px-4 py-3 text-[11px] uppercase tracking-[0.2em]">
      <div class="flex items-center gap-3">
        <span class="dot"></span>
        <span class="text-ok">SVC-01</span>
        <span class="hidden text-muted sm:inline">Domain &amp; URL Checker</span>
      </div>
      <div class="flex items-center gap-4 text-muted">
        <span>Port 8001</span>
        <span id="clock" class="tabular-nums">--:--:-- UTC</span>
      </div>
    </div>
  </header>

  <main class="mx-auto max-w-3xl px-4 pb-16 pt-14 sm:pt-20">
    <section class="reveal">
      <p class="eyebrow">// WHOIS &middot; DNS &middot; TLS &middot; threat intel &middot; URL heuristics</p>
      <h1 class="font-display mt-4 text-5xl font-bold uppercase leading-[0.9] tracking-tight text-white sm:text-7xl">Domain<br><span class="text-ok">Recon</span><span class="caret">_</span></h1>
      <p class="mt-5 max-w-lg text-sm leading-relaxed text-muted">Pull registration, DNS, certificate, reputation and URL-pattern intel for any domain or URL. Fresh or soon-to-expire registrations, missing SPF / DMARC, untrusted certificates, security-vendor detections and deceptive link structures are classic markers of phishing and malware infrastructure.</p>
    </section>

    <form id="scan-form" class="panel reveal mt-10" style="--d:120ms" autocomplete="off">
      <label for="domain" class="label flex items-center justify-between border-b border-[var(--line)] px-4 py-2.5">
        <span>Target &middot; domain or URL</span>
        <span class="hidden sm:inline">Enter &crarr; to scan</span>
      </label>
      <div class="flex flex-col sm:flex-row">
        <div class="flex flex-1 items-center gap-3 px-4">
          <span class="prompt">$ scan</span>
          <input id="domain" type="text" required autofocus spellcheck="false" placeholder="e.g. google.com"
            class="console-input min-w-0 flex-1 bg-transparent py-4 outline-none">
        </div>
        <button id="scan-btn" type="submit" class="btn">
          <span class="spinner" aria-hidden="true"></span>
          <span id="btn-label">Scan Domain</span>
        </button>
      </div>
      <div class="scanbar"></div>
    </form>

    <div id="alert" class="reveal mt-6 hidden" role="alert">
      <div class="alert flex items-start gap-3 px-4 py-3 text-sm">
        <span class="font-display font-bold text-[var(--err)]">[!]</span>
        <div>
          <p class="label" style="color: var(--err)">Lookup error</p>
          <p id="alert-msg" class="mt-1"></p>
        </div>
      </div>
    </div>

    <section id="risk" class="panel reveal mt-6 hidden" aria-live="polite">
      <div class="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] px-5 py-4">
        <div>
          <p class="label">Composite verdict &middot; 5 checks</p>
          <div class="mt-1 flex items-center gap-2">
            <h2 class="font-display text-2xl font-semibold text-white">Threat Score</h2>
            <span class="tip">
              <button type="button" class="tip-btn" aria-label="How is the score calculated?" aria-describedby="tip-risk">?</button>
              <span id="tip-risk" role="tooltip" class="tip-body"><b>How the score works.</b> Points from five checks, each capped: threat intelligence up to 50, domain age &amp; expiry 25, SSL 25, email authentication 15 and URL patterns 30. The total is capped at 100, so reaching Critical takes problems in several areas at once.</span>
            </span>
          </div>
        </div>
        <span id="risk-badge" class="badge"></span>
      </div>

      <div class="grid gap-6 p-5 sm:grid-cols-[240px_1fr] sm:items-center">
        <div class="gauge">
          <!-- r = 80: circumference 502.65, the 270° arc is 376.99, each risk zone 94.25 (drawn 2 shorter for a gap) -->
          <svg viewBox="0 0 200 200" aria-hidden="true">
            <g transform="rotate(135 100 100)">
              <circle class="zone" data-tone="ok" cx="100" cy="100" r="80" stroke-dasharray="92.25 502.65"></circle>
              <circle class="zone" data-tone="warn" cx="100" cy="100" r="80" stroke-dasharray="92.25 502.65" stroke-dashoffset="-94.25"></circle>
              <circle class="zone" data-tone="high" cx="100" cy="100" r="80" stroke-dasharray="92.25 502.65" stroke-dashoffset="-188.5"></circle>
              <circle class="zone" data-tone="crit" cx="100" cy="100" r="80" stroke-dasharray="92.25 502.65" stroke-dashoffset="-282.74"></circle>
              <circle id="gauge-arc" class="gauge-arc" cx="100" cy="100" r="80" stroke-dasharray="0 502.65"></circle>
            </g>
            <line class="gauge-tick" x1="16.85" y1="65.56" x2="10.38" y2="62.88"></line>
            <line class="gauge-tick" x1="100" y1="10" x2="100" y2="3"></line>
            <line class="gauge-tick" x1="183.15" y1="65.56" x2="189.62" y2="62.88"></line>
            <text class="gauge-end" x="40" y="180" text-anchor="middle">0</text>
            <text class="gauge-end" x="160" y="180" text-anchor="middle">100</text>
          </svg>
          <div class="gauge-center">
            <p id="risk-score" class="gauge-score">0</p>
            <p class="gauge-max">/ 100</p>
            <p id="risk-level" class="gauge-level"></p>
          </div>
        </div>

        <div class="min-w-0">
          <p id="risk-title" class="verdict-title" style="font-size: 24px"></p>
          <p id="risk-body" class="mt-2 text-sm leading-relaxed text-[var(--text)]"></p>
          <p id="risk-reasons-label" class="label mt-5"></p>
          <ul id="risk-reasons" class="mt-1"></ul>
          <details id="risk-more" class="hidden">
            <summary id="risk-more-label" class="label"></summary>
            <ul id="risk-reasons-more"></ul>
          </details>
        </div>
      </div>

      <div class="grid grid-cols-4 gap-1.5 border-t border-[var(--line)] px-5 py-4">
        <div id="rl-low" class="scale-seg" data-tone="ok"><span>0&ndash;24</span>Low</div>
        <div id="rl-medium" class="scale-seg" data-tone="warn"><span>25&ndash;49</span>Medium</div>
        <div id="rl-high" class="scale-seg" data-tone="high"><span>50&ndash;74</span>High</div>
        <div id="rl-critical" class="scale-seg" data-tone="crit"><span>75&ndash;100</span>Critical</div>
      </div>
    </section>

    <section id="result" class="panel reveal mt-6 hidden" aria-live="polite">
      <div class="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--line)] p-5">
        <div class="min-w-0">
          <p class="label">Target</p>
          <h2 id="r-domain" class="font-display mt-1 break-all text-3xl font-semibold text-white"></h2>
          <p id="r-meta" class="mt-1 text-xs text-muted"></p>
        </div>
        <span id="r-badge" class="badge"></span>
      </div>

      <div class="grid grid-cols-1 gap-px bg-[var(--line)] sm:grid-cols-3">
        <div class="cell reveal" style="--d:60ms">
          <p class="label">Created</p>
          <p id="r-created" class="cell-value"></p>
          <p class="cell-sub"></p>
        </div>
        <div class="cell reveal" style="--d:120ms">
          <p class="label">Age</p>
          <p id="r-age" class="cell-value"></p>
          <p id="r-age-sub" class="cell-sub"></p>
        </div>
        <div class="cell reveal" style="--d:180ms">
          <p class="label">Registrar</p>
          <p id="r-registrar" class="cell-value is-small"></p>
          <p class="cell-sub"></p>
        </div>
        <div class="cell reveal" style="--d:240ms">
          <p class="label">Expires</p>
          <p id="r-expires" class="cell-value"></p>
          <p class="cell-sub"></p>
        </div>
        <div id="c-left" class="cell flag reveal sm:col-span-2" style="--d:300ms">
          <p class="label">Days Left</p>
          <p id="r-left" class="cell-value"></p>
          <p id="r-left-sub" class="cell-sub"></p>
        </div>
      </div>

      <div id="life" class="border-t border-[var(--line)] px-5 pb-5 pt-4">
        <div class="label flex justify-between"><span>Registration lifespan</span><span id="life-pct"></span></div>
        <div class="life-track mt-8">
          <div id="life-fill" class="life-fill"></div>
          <div id="life-marker" class="life-marker"><span id="life-tag">TODAY</span></div>
        </div>
        <div class="mt-3 flex justify-between text-[11px] text-muted"><span id="life-start"></span><span id="life-end"></span></div>
      </div>

      <details class="raw border-t border-[var(--line)]">
        <summary class="label px-5 py-3">Raw response &middot; DomainScan contract</summary>
        <pre id="raw" class="overflow-x-auto px-5 pb-5 text-xs leading-relaxed text-muted"></pre>
      </details>
    </section>

    <section id="dns" class="panel reveal mt-6 hidden" style="--d:80ms" aria-live="polite">
      <div class="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] px-5 py-4">
        <div>
          <p class="label">Hosting &amp; email protection</p>
          <h3 class="font-display mt-1 text-2xl font-semibold text-white">DNS &amp; Mail Security</h3>
        </div>
        <span id="dns-summary" class="label"></span>
      </div>

      <div id="verdict" class="verdict reveal" style="--d:120ms" role="status">
        <span id="v-icon" class="verdict-icon" aria-hidden="true"></span>
        <div class="min-w-0">
          <p id="v-title" class="verdict-title"></p>
          <p id="v-body" class="mt-1 text-sm leading-relaxed text-[var(--text)]"></p>
          <p id="v-hint" class="mt-2 text-xs text-muted"></p>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-px border-t border-[var(--line)] bg-[var(--line)] sm:grid-cols-2">
        <div id="c-spf" class="cell flag reveal" style="--d:180ms">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="flex items-center gap-2">
                <p class="rec-key">SPF</p>
                <span class="tip">
                  <button type="button" class="tip-btn" aria-label="What is SPF?" aria-describedby="tip-spf">?</button>
                  <span id="tip-spf" role="tooltip" class="tip-body"><b>Sender Policy Framework.</b> A public list of the mail servers allowed to send email for this domain. Technical check: a TXT record starting with <code>v=spf1</code>.</span>
                </span>
              </div>
              <p class="label mt-2">Approved sender list</p>
            </div>
            <span class="badge"><span id="b-spf"></span></span>
          </div>
          <p class="protects mt-4"><span>Protects against</span>emails sent from servers the domain owner never approved.</p>
          <p id="d-spf" class="cell-sub mt-2"></p>
        </div>
        <div id="c-dmarc" class="cell flag reveal" style="--d:240ms">
          <div class="flex items-start justify-between gap-3">
            <div>
              <div class="flex items-center gap-2">
                <p class="rec-key">DMARC</p>
                <span class="tip">
                  <button type="button" class="tip-btn" aria-label="What is DMARC?" aria-describedby="tip-dmarc">?</button>
                  <span id="tip-dmarc" role="tooltip" class="tip-body"><b>Domain-based Message Authentication.</b> The domain's instruction to receiving mail servers: reject or quarantine emails that fail authentication. Technical check: a TXT record starting with <code>v=DMARC1</code> at <code>_dmarc.&lt;domain&gt;</code>.</span>
                </span>
              </div>
              <p class="label mt-2">Anti-spoofing policy</p>
            </div>
            <span class="badge"><span id="b-dmarc"></span></span>
          </div>
          <p class="protects mt-4"><span>Protects against</span>fake emails impersonating this domain landing in inboxes.</p>
          <p id="d-dmarc" class="cell-sub mt-2"></p>
        </div>
      </div>

      <div class="grid gap-px border-t border-[var(--line)] bg-[var(--line)]">
        <div class="reveal grid gap-3 bg-[var(--panel)] px-5 py-4 sm:grid-cols-[230px_1fr] sm:gap-6" style="--d:300ms">
          <div>
            <p class="rec-title">Server IP Addresses<span id="n-a" class="rec-count"></span></p>
            <p class="rec-sub">Where the website files and servers are physically hosted</p>
            <p class="rec-tech">A record</p>
          </div>
          <ul id="l-a" class="chips"></ul>
        </div>
        <div class="reveal grid gap-3 bg-[var(--panel)] px-5 py-4 sm:grid-cols-[230px_1fr] sm:gap-6" style="--d:360ms">
          <div>
            <p class="rec-title">Nameservers<span id="n-ns" class="rec-count"></span></p>
            <p class="rec-sub">DNS traffic controllers</p>
            <p class="rec-tech">NS record</p>
          </div>
          <ul id="l-ns" class="chips"></ul>
        </div>
        <div class="reveal grid gap-3 bg-[var(--panel)] px-5 py-4 sm:grid-cols-[230px_1fr] sm:gap-6" style="--d:420ms">
          <div>
            <p class="rec-title">Mail Servers<span id="n-mx" class="rec-count"></span></p>
            <p class="rec-sub">Servers that accept emails for this domain</p>
            <p class="rec-tech">MX record</p>
          </div>
          <ul id="l-mx" class="chips"></ul>
        </div>
      </div>

      <p id="dns-empty" class="hidden border-t border-[var(--line)] px-5 py-3 text-xs text-[var(--warn)]">[!] No DNS records found &middot; this domain doesn't seem to exist or isn't online.</p>
    </section>

    <section id="ssl" class="panel reveal mt-6 hidden" style="--d:80ms" aria-live="polite">
      <div class="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] px-5 py-4">
        <div>
          <p class="label">Encryption &amp; identity</p>
          <h3 class="font-display mt-1 text-2xl font-semibold text-white">SSL / TLS Certificate</h3>
        </div>
        <span id="ssl-badge" class="badge"></span>
      </div>

      <div id="ssl-verdict" class="verdict reveal" style="--d:120ms" role="status">
        <span id="sv-icon" class="verdict-icon" aria-hidden="true"></span>
        <div class="min-w-0">
          <p id="sv-title" class="verdict-title"></p>
          <p id="sv-body" class="mt-1 text-sm leading-relaxed text-[var(--text)]"></p>
          <p id="sv-hint" class="mt-2 break-words text-xs text-muted"></p>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-px border-t border-[var(--line)] bg-[var(--line)] sm:grid-cols-3">
        <div class="cell reveal" style="--d:180ms">
          <div class="flex items-center gap-2">
            <p class="label">Issued by</p>
            <span class="tip">
              <button type="button" class="tip-btn" aria-label="What is a certificate authority?" aria-describedby="tip-ca">?</button>
              <span id="tip-ca" role="tooltip" class="tip-body"><b>Certificate authority.</b> A company that browsers trust to confirm a website really controls its domain before issuing it a certificate.</span>
            </span>
          </div>
          <p id="s-issuer" class="cell-value is-small"></p>
          <p class="cell-sub">Who vouches for this site's identity</p>
        </div>
        <div class="cell reveal" style="--d:240ms">
          <p class="label">Expires</p>
          <p id="s-expires" class="cell-value"></p>
          <p class="cell-sub">Certificate end date</p>
        </div>
        <div id="c-ssl-left" class="cell flag reveal" style="--d:300ms">
          <p class="label">Days Remaining</p>
          <p id="s-left" class="cell-value"></p>
          <p id="s-left-sub" class="cell-sub"></p>
        </div>
      </div>

      <div class="border-t border-[var(--line)]">
        <p class="label px-5 py-3">What was verified</p>
        <ul class="grid grid-cols-1 gap-px border-t border-[var(--line)] bg-[var(--line)] sm:grid-cols-2">
          <li id="k-reach" class="check reveal" style="--d:340ms"><span id="km-reach" class="check-mark" aria-hidden="true"></span>Secure HTTPS connection on port 443</li>
          <li id="k-trust" class="check reveal" style="--d:380ms"><span id="km-trust" class="check-mark" aria-hidden="true"></span>Issued by a trusted authority</li>
          <li id="k-host" class="check reveal" style="--d:420ms"><span id="km-host" class="check-mark" aria-hidden="true"></span>Issued for this exact domain</li>
          <li id="k-date" class="check reveal" style="--d:460ms"><span id="km-date" class="check-mark" aria-hidden="true"></span>Within its validity dates</li>
        </ul>
        <p id="ssl-note" class="hidden border-t border-[var(--line)] px-5 py-3 text-[11px] text-muted">&ndash; Not checked: verification stops at the first problem it finds.</p>
      </div>
    </section>

    <section id="threat" class="panel reveal mt-6 hidden" style="--d:80ms" aria-live="polite">
      <div class="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] px-5 py-4">
        <div>
          <p class="label">Reputation &amp; blocklists</p>
          <h3 class="font-display mt-1 text-2xl font-semibold text-white">Malware &amp; Threat Intelligence</h3>
        </div>
        <span id="threat-badge" class="badge"></span>
      </div>

      <div id="threat-verdict" class="verdict reveal" style="--d:120ms" role="status">
        <span id="tv-icon" class="verdict-icon" aria-hidden="true"></span>
        <div class="min-w-0">
          <p id="tv-title" class="verdict-title"></p>
          <p id="tv-body" class="mt-1 text-sm leading-relaxed text-[var(--text)]"></p>
          <p id="tv-hint" class="mt-2 break-words text-xs text-muted"></p>
        </div>
      </div>

      <div id="threat-action" class="action reveal" style="--d:160ms">
        <p class="label">Recommended action</p>
        <div class="mt-3 flex items-start gap-3">
          <span id="ta-icon" class="action-icon" aria-hidden="true"></span>
          <p class="text-[15px] leading-relaxed text-white"><strong id="ta-head" class="action-head"></strong> <span id="ta-text"></span></p>
        </div>
        <ul id="ta-steps" class="action-steps mt-2"></ul>
      </div>

      <div class="grid grid-cols-1 gap-px border-t border-[var(--line)] bg-[var(--line)] sm:grid-cols-3">
        <div id="c-vt" class="cell flag reveal" style="--d:180ms">
          <div class="flex items-center gap-2">
            <p class="label">Vendor detections</p>
            <span class="tip">
              <button type="button" class="tip-btn" aria-label="What are vendor detections?" aria-describedby="tip-vt">?</button>
              <span id="tip-vt" role="tooltip" class="tip-body"><b>VirusTotal</b> checks the domain against dozens of antivirus and web-reputation services. This is how many of them currently report it as malicious.</span>
            </span>
          </div>
          <p id="t-vt" class="cell-value is-big"></p>
          <p id="t-vt-sub" class="cell-sub"></p>
        </div>
        <div id="c-sb" class="cell flag reveal" style="--d:240ms">
          <div class="flex items-center gap-2">
            <p class="label">Google Safe Browsing</p>
            <span class="tip">
              <button type="button" class="tip-btn" aria-label="What is Google Safe Browsing?" aria-describedby="tip-sb">?</button>
              <span id="tip-sb" role="tooltip" class="tip-body"><b>Google Safe Browsing</b> keeps a live list of phishing and malware sites. When a site is on it, Chrome and Android show visitors a full-page red warning before letting them in.</span>
            </span>
          </div>
          <p id="t-sb" class="cell-value"></p>
          <p class="cell-sub">Google's global protection system, built into Chrome and Android</p>
        </div>
        <div class="cell reveal" style="--d:300ms">
          <p class="label">Full report</p>
          <a id="vt-link" class="vt-link" target="_blank" rel="noopener noreferrer">Open on VirusTotal &nearr;</a>
          <p class="cell-sub">Per-vendor results and history</p>
        </div>
      </div>

      <div class="reveal grid gap-3 border-t border-[var(--line)] px-5 py-4 sm:grid-cols-[190px_1fr] sm:gap-6" style="--d:320ms">
        <div>
          <p class="rec-title">Flagged by</p>
          <p class="rec-sub">Security engines that report this domain as malicious</p>
        </div>
        <ul id="t-vendors" class="chips"></ul>
      </div>

      <div class="reveal border-t border-[var(--line)] px-5 py-4" style="--d:360ms">
        <p class="label">Vendor detection scale</p>
        <div class="mt-3 grid grid-cols-3 gap-1.5">
          <div id="sc-clean" class="scale-seg" data-tone="ok"><span>0</span>Clean</div>
          <div id="sc-low" class="scale-seg" data-tone="warn"><span>1&ndash;2</span>Low confidence</div>
          <div id="sc-high" class="scale-seg" data-tone="err"><span>3+</span>Malicious</div>
        </div>
      </div>
    </section>

    <section id="heur" class="panel reveal mt-6 hidden" style="--d:80ms" aria-live="polite">
      <div class="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] px-5 py-4">
        <div>
          <p class="label">Structure &amp; deception patterns</p>
          <h3 class="font-display mt-1 text-2xl font-semibold text-white">URL Heuristics &amp; Phishing Patterns</h3>
        </div>
        <span id="heur-badge" class="badge"></span>
      </div>

      <div id="heur-verdict" class="verdict reveal" style="--d:120ms" role="status">
        <span id="hv-icon" class="verdict-icon" aria-hidden="true"></span>
        <div class="min-w-0">
          <p id="hv-title" class="verdict-title"></p>
          <p id="hv-body" class="mt-1 text-sm leading-relaxed text-[var(--text)]"></p>
          <p id="hv-hint" class="mt-2 break-all text-xs text-muted"></p>
        </div>
      </div>

      <div id="heur-findings-wrap" class="hidden border-t border-[var(--line)]">
        <p class="label px-5 py-3">Red flags found</p>
        <ol id="heur-findings" class="findings border-t border-[var(--line)]"></ol>
      </div>

      <div class="border-t border-[var(--line)]">
        <p class="label px-5 py-3">Patterns checked</p>
        <ul id="heur-checks" class="grid grid-cols-1 gap-px border-t border-[var(--line)] bg-[var(--line)] sm:grid-cols-2"></ul>
      </div>
    </section>

    <section class="panel reveal mt-6" style="--d:240ms">
      <div class="label flex items-center justify-between border-b border-[var(--line)] px-4 py-2.5"><span>Session log</span><span>Last 8</span></div>
      <ol id="log" class="log p-4 text-xs"><li id="log-empty" class="text-muted">Awaiting target&hellip;</li></ol>
    </section>

    <footer class="reveal mt-10 flex flex-wrap justify-between gap-2 text-[11px] text-muted" style="--d:320ms">
      <span>Temporary test console &middot; not part of the API contract</span>
      <a href="/docs" class="text-ok hover:underline">GET /docs &rarr;</a>
    </footer>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const form = $("scan-form");
    const input = $("domain");
    const button = $("scan-btn");
    const DASH = "—";

    const tick = () => { $("clock").textContent = new Date().toISOString().slice(11, 19) + " UTC"; };
    tick();
    setInterval(tick, 1000);

    const plural = (n, word) => `${Math.abs(n).toLocaleString()} ${word}${Math.abs(n) === 1 ? "" : "s"}`;

    function setLoading(on) {
      form.classList.toggle("is-loading", on);
      button.disabled = on;
      $("btn-label").textContent = on ? "Scanning" : "Scan Domain";
    }

    // textContent, never innerHTML: WHOIS data comes from third-party servers
    function setText(id, value) {
      $(id).textContent = value ?? DASH;
    }

    function showAlert(message) {
      setText("alert-msg", message);
      $("alert").classList.remove("hidden");
    }

    function log(tone, text) {
      $("log-empty")?.remove();
      const item = document.createElement("li");
      const time = document.createElement("span");
      const tag = document.createElement("span");
      const msg = document.createElement("span");
      time.className = "text-muted";
      time.textContent = new Date().toISOString().slice(11, 19);
      tag.className = "tag";
      tag.dataset.tone = tone;
      tag.textContent = { muted: "[*]", ok: "[+]", warn: "[!]", high: "[!]", err: "[x]", crit: "[x]" }[tone];
      msg.className = "break-all";
      msg.textContent = text;
      item.append(time, tag, msg);
      $("log").prepend(item);
      while ($("log").children.length > 8) $("log").lastElementChild.remove();
    }

    // Under 30 days left is the window that matters for short-lived phishing domains
    function expiryStatus(whois) {
      if (whois.error) return ["err", "No WHOIS data"];
      const left = whois.expires_days_left;
      if (left == null) return ["muted", "Expiry unknown"];
      if (left < 0) return ["err", "Expired"];
      if (left < 30) return ["warn", "Expiring soon"];
      return ["ok", "Registered"];
    }

    function renderLifespan(whois, tone) {
      const life = $("life");
      const known = whois.age_days != null && whois.expires_days_left != null;
      life.classList.toggle("hidden", !known);
      if (!known) return;

      const total = whois.age_days + whois.expires_days_left;
      const pct = total > 0 ? Math.min(100, Math.max(0, (whois.age_days / total) * 100)) : 100;
      life.dataset.tone = tone;
      setText("life-pct", `${pct.toFixed(0)}% elapsed`);
      setText("life-start", whois.created);
      setText("life-end", whois.expires);
      $("life-tag").style.transform = pct > 85 ? "translateX(-100%)" : pct < 15 ? "none" : "translateX(-50%)";

      // Reset to 0 first so the bar sweeps in on every scan
      $("life-fill").style.width = "0";
      $("life-marker").style.left = "0";
      requestAnimationFrame(() => requestAnimationFrame(() => {
        $("life-fill").style.width = `${pct}%`;
        $("life-marker").style.left = `${pct}%`;
      }));
    }

    function chips(id, items, emptyText) {
      const list = $(id);
      list.replaceChildren();
      for (const item of items.length ? items : [null]) {
        const chip = document.createElement("li");
        chip.className = item ? "chip" : "chip is-empty";
        chip.textContent = item ?? emptyText;
        list.append(chip);
      }
    }

    const EMPTY_RECORDS = { a: "No IP address found", ns: "No nameservers found", mx: "No Mail Service" };

    // Status line under each check: [when set up, when missing]
    const GUARDS = {
      spf: [
        "Set up · receiving mail servers can verify an email came from an approved server.",
        "Missing · receiving mail servers can't verify who is allowed to send as this domain.",
      ],
      dmarc: [
        "Set up · the domain tells receivers how to handle emails that fail the checks.",
        "Missing · nothing tells receivers to block fake emails using this domain's name.",
      ],
    };

    // Overall email verdict: [tone, icon, title, message]
    const VERDICTS = {
      none: ["err", "⚠️", "Email Spoofing Risk", "Senders are not authenticated. Attackers can forge emails pretending to come from this domain."],
      partial: ["warn", "⚠️", "Partial Protection", "Email authentication is incomplete."],
      full: ["ok", "🛡️", "Fully Protected", "Emails from this domain cannot be easily spoofed."],
    };

    function renderVerdict(spf, dmarc) {
      const level = spf && dmarc ? "full" : spf || dmarc ? "partial" : "none";
      const [tone, icon, title, message] = VERDICTS[level];
      $("verdict").dataset.tone = tone;
      setText("v-icon", icon);
      setText("v-title", title);
      setText("v-body", message);
      setText("v-hint",
        level === "full" ? "SPF and DMARC are both set up."
        : level === "none" ? "Missing: SPF and DMARC."
        : spf ? "SPF is set up, but DMARC is missing, so nothing tells receivers to reject emails that fail the check."
        : "DMARC is set up, but SPF is missing, so there's no list of approved sending servers to check against.");
    }

    function renderDns(dns) {
      const records = { a: dns.a || [], ns: dns.ns || [], mx: dns.mx || [] };
      for (const [key, items] of Object.entries(records)) {
        chips(`l-${key}`, items, EMPTY_RECORDS[key]);
        setText(`n-${key}`, String(items.length));
      }

      const status = { spf: dns.spf === true, dmarc: dns.dmarc === true };
      for (const [key, on] of Object.entries(status)) {
        $(`c-${key}`).dataset.tone = on ? "ok" : "err";
        setText(`b-${key}`, on ? "Protected" : "Not Configured");
        setText(`d-${key}`, GUARDS[key][on ? 0 : 1]);
      }
      renderVerdict(status.spf, status.dmarc);

      const total = records.a.length + records.ns.length + records.mx.length;
      setText("dns-summary", `${plural(total, "record")} found`);
      $("dns-empty").classList.toggle("hidden", total > 0);
    }

    // [tone, icon, badge, title, plain-language meaning]
    const SSL_STATES = {
      valid: ["ok", "🔒", "Valid & Trusted", "Secure Connection",
        "Traffic between visitors and this site is encrypted, and a trusted authority has confirmed the certificate belongs to this domain."],
      expired: ["err", "⛔", "Expired", "Expired Certificate",
        "The certificate is past its end date. Browsers show a full-page security warning and the connection can no longer be trusted, which often points to a neglected or abandoned site."],
      untrusted: ["err", "⚠️", "Untrusted", "Untrusted Certificate",
        "The certificate failed verification, so there is no proof this site is who it claims to be. Browsers warn visitors, and phishing and traffic-interception setups often look exactly like this."],
      invalid: ["err", "🔓", "Invalid", "No Secure Connection",
        "The site doesn't offer a working HTTPS connection, so anything sent to it, such as passwords or card numbers, is not protected. Legitimate login and payment pages always use HTTPS."],
      skipped: ["warn", "🚫", "Not Scanned", "Internal Address",
        "This domain points to a private or internal network address, so the check was skipped to stop the scanner from probing internal systems. A public domain pointing inside a private network is unusual."],
    };

    // Badge state + failed check, read from the scanner's error text
    // (the messages are defined in scanners/ssl_check.py, inside this same service)
    function sslDiagnosis(ssl) {
      if (ssl.valid) return ["valid", null];
      const reason = (ssl.error || "").toLowerCase();
      if (reason.startsWith("skipped")) return ["skipped", null];
      if (reason.includes("expired")) return ["expired", "date"];
      if (reason.includes("not valid yet")) return ["untrusted", "date"];
      if (reason.includes("mismatch")) return ["untrusted", "host"];
      if (/self-signed|untrusted|revoked/.test(reason)) return ["untrusted", "trust"];
      return ["invalid", "reach"];
    }

    const CHECK_MARKS = { pass: ["ok", "✓"], fail: ["err", "✗"], skip: ["muted", "–"] };

    function renderSsl(ssl) {
      const [state, failed] = sslDiagnosis(ssl);
      const [tone, icon, badge, title, message] = SSL_STATES[state];
      $("ssl-badge").dataset.tone = tone;
      setText("ssl-badge", badge);
      $("ssl-verdict").dataset.tone = tone;
      setText("sv-icon", icon);
      setText("sv-title", title);
      setText("sv-body", message);
      setText("sv-hint", ssl.valid
        ? `Issued by ${ssl.issuer ?? "an unnamed authority"} · valid until ${ssl.expires}`
        : `Technical reason: ${ssl.error ?? "unknown"}`);

      setText("s-issuer", ssl.issuer);
      setText("s-expires", ssl.expires);
      const left = ssl.days_left;
      $("c-ssl-left").dataset.tone = left == null ? "muted" : left < 7 ? "warn" : "ok";
      setText("s-left", left == null ? null : `${plural(left, "day")} remaining`);
      setText("s-left-sub",
        left == null ? "Unavailable · no verified certificate"
        : left < 7 ? "Expires within a week · renewal may be failing"
        : left < 30 ? "Renewal due soon · usually automatic"
        : "Comfortably within its validity period");

      // Verification stops at the first problem, so checks after it are honestly "not checked";
      // a certificate-level failure still proves the HTTPS connection itself worked
      let unchecked = false;
      for (const key of ["reach", "trust", "host", "date"]) {
        const connected = key === "reach" && failed !== null && failed !== "reach";
        const status = ssl.valid || connected ? "pass" : key === failed ? "fail" : "skip";
        const [markTone, mark] = CHECK_MARKS[status];
        $(`k-${key}`).dataset.tone = markTone;
        setText(`km-${key}`, mark);
        unchecked ||= status === "skip";
      }
      $("ssl-note").classList.toggle("hidden", !unchecked);
    }

    // Isolated detections are common false positives (even major, well-known sites collect one),
    // so the console only calls a domain malicious from 3 vendors up, or when Google Safe Browsing lists it
    const MALICIOUS_AT = 3;

    const listNames = (names) => names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;

    // [tone, icon, badge, title, plain-language meaning(hits, unsafe, vendors)]
    const THREAT_STATES = {
      clean: ["ok", "🛡️", "Clean & Safe", "No Known Threats", () =>
        "None of the security vendors checked by VirusTotal, including Google Safe Browsing, report this domain for malware, phishing or scams."],
      low: ["warn", "⚠️", "Low-Confidence Flag", "Isolated Detection", (hits, unsafe, vendors) =>
        `${vendors.length ? listNames(vendors) : plural(hits, "security vendor")} flagged this domain, while Google Safe Browsing and the other vendors did not.`],
      malicious: ["err", "☣️", "Flagged as Malicious", "Malicious Domain", (hits, unsafe, vendors) => {
        // Google Safe Browsing is itself one of the counted engines, so don't count it twice
        const others = vendors.length ? vendors.filter((name) => name !== "Google Safe Browsing").length : hits;
        const reported = others
          ? `${plural(others, "security vendor")} ${others === 1 ? "reports" : "report"} this domain for malware, phishing or other malicious activity`
          : "Google Safe Browsing lists this domain as unsafe";
        const google = others && unsafe ? ", and Google Safe Browsing lists it as unsafe" : "";
        return `${reported}${google}. Do not enter passwords or payment details, and do not download anything from it.`;
      }],
      nodata: ["muted", "❔", "No Data", "No Reputation History", () =>
        "VirusTotal has no analysis of this domain yet. Unknown isn't the same as safe: newly registered phishing domains usually have no history yet."],
      unavailable: ["warn", "📡", "Unavailable", "Reputation Check Unavailable", () =>
        "The VirusTotal lookup didn't complete, so this domain's reputation is unknown, not confirmed safe."],
    };

    // What the analyst should do: [tone, icon, headline, advice(hits, unsafe, vendors), next steps]
    const ACTIONS = {
      clean: ["ok", "✅", "Clean", "Safe to visit. No malicious indicators found across 90+ threat engines.", [
        "Brand-new phishing domains are often not flagged yet, so also check the domain age and certificate above.",
      ]],
      low: ["warn", "⚠️", "Advisory", (hits, unsafe, vendors) =>
        `Likely a false positive from an aggressive heuristic engine${vendors.length ? ` (here: ${listNames(vendors)})` : ""}. Safe for normal browsing, but avoid entering sensitive credentials if unfamiliar.`, [
        "Open the full VirusTotal report to see exactly what was detected.",
        "Re-scan in a few days: real threats usually pick up more detections quickly.",
      ]],
      malicious: ["err", "⛔", "Danger", (hits, unsafe) =>
        `${hits >= MALICIOUS_AT ? `Multiple major security vendors${unsafe ? " and Google Safe Browsing" : ""} actively block` : "Google Safe Browsing actively blocks"} this domain. Do not open or interact with it.`, [
        "Block it on your DNS filter, web proxy or email gateway.",
        "If anyone already entered credentials there, reset those passwords and alert your security team.",
      ]],
      nodata: ["muted", "❔", "Unknown", "No reputation history to go on. Treat links to this domain with caution until it has been verified.", [
        "Confirm the link through another channel (official website, phone) before entering any information.",
      ]],
      unavailable: ["warn", "🔁", "Retry", "The reputation check didn't complete, so there is no verdict yet.", [
        "Scan again in about a minute: the free VirusTotal plan allows 4 lookups per minute.",
      ]],
    };

    function renderAction(state, hits, unsafe, vendors) {
      const [tone, icon, head, advice, steps] = ACTIONS[state];
      $("threat-action").dataset.tone = tone;
      setText("ta-icon", icon);
      setText("ta-head", `${head}:`);
      setText("ta-text", typeof advice === "function" ? advice(hits, unsafe, vendors) : advice);
      const list = $("ta-steps");
      list.replaceChildren();
      for (const step of steps) {
        const item = document.createElement("li");
        item.textContent = step;
        list.append(item);
      }
    }

    function threatState(bl) {
      // Fail closed: the scanner's fallback carries virustotal 0 / "clean", which must never read as safe
      if (bl.error || typeof bl.virustotal !== "number") return /^not found/i.test(bl.error || "") ? "nodata" : "unavailable";
      if (bl.virustotal >= MALICIOUS_AT || bl.safebrowsing === "unsafe") return "malicious";
      return bl.virustotal > 0 ? "low" : "clean";
    }

    function renderBlacklist(bl, domain) {
      const state = threatState(bl);
      const [tone, icon, badge, title, message] = THREAT_STATES[state];
      const checked = state !== "nodata" && state !== "unavailable";
      const hits = checked ? bl.virustotal : null;
      const unsafe = checked && bl.safebrowsing === "unsafe";
      const vendors = checked && Array.isArray(bl.flagged_by) ? bl.flagged_by : [];

      $("threat-badge").dataset.tone = tone;
      setText("threat-badge", badge);
      $("threat-verdict").dataset.tone = tone;
      setText("tv-icon", icon);
      setText("tv-title", title);
      setText("tv-body", message(hits, unsafe, vendors));
      renderAction(state, hits, unsafe, vendors);
      setText("tv-hint", checked
        ? "Source: VirusTotal API v3 · repeat scans within 10 minutes reuse the last result"
        : `Technical reason: ${bl.error ?? "no data returned"}`);

      const level = hits == null ? null : hits === 0 ? "clean" : hits < MALICIOUS_AT ? "low" : "high";
      $("c-vt").dataset.tone = { clean: "ok", low: "warn", high: "err" }[level] ?? "muted";
      setText("t-vt", hits == null ? null : String(hits));
      setText("t-vt-sub", hits == null ? "Not checked" : `${hits === 1 ? "security vendor" : "security vendors"} flagged this domain`);
      $("c-sb").dataset.tone = !checked ? "muted" : unsafe ? "err" : "ok";
      setText("t-sb", !checked ? null : unsafe ? "Unsafe" : "Clean");
      $("vt-link").href = `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain || "")}`;
      for (const key of ["clean", "low", "high"]) $(`sc-${key}`).dataset.active = String(key === level);

      $("t-vendors").dataset.tone = state === "malicious" ? "err" : { clean: "ok", low: "warn" }[level] ?? "muted";
      chips("t-vendors", vendors,
        !checked ? "Not checked" : hits === 0 ? "Zero security engines flagged this domain" : "Vendor names not available");
    }

    // Keyed by the title before ":" in each finding (titles are defined in scanners/heuristics_check.py):
    // [check label when the pattern is absent, why the pattern is dangerous]
    const HEURISTIC_PATTERNS = {
      "IP address instead of a domain name": ["Real domain name, not a raw IP address",
        "Legitimate services use domain names. A raw IP address hides who owns the site and is typical of throwaway phishing servers and hacked machines."],
      "Unusually long URL": ["Normal URL length (75 characters or less)",
        "Very long links push the real domain out of view, especially on phones, and bury it among misleading text so you can't easily tell where the link leads."],
      "Too many subdomains": ["Reasonable number of subdomains",
        "Attackers stack subdomains so a link starts with a trusted name, like paypal.com.account-check.xyz, while the real owner is the domain at the very end."],
      "Hidden destination behind an @ symbol": ["No @ redirection trick",
        "Browsers ignore everything before an @ in the address, so http://paypal.com@evil.tk actually opens evil.tk. It shows you a trusted name while sending you elsewhere."],
      "Hyphen-stuffed domain name": ["No hyphen-stuffed domain name",
        "Chains of hyphenated words such as secure-login-paypal-verify are a hallmark of phishing domains: they mimic a brand while avoiding its real, protected name."],
      "Sensitive keywords in a suspicious context": ["No bait keywords out of context",
        "Words like login, verify or a brand name placed where they don't belong borrow trust and create urgency, the core ingredients of a credential-phishing page."],
      "High-risk domain ending": ["Not a high-risk domain ending",
        "This ending is cheap or free to register and heavily over-represented in phishing and malware reports. Real banks and payment services rarely use it."],
      "Look-alike characters from another alphabet": ["No look-alike characters",
        "Letters from alphabets like Cyrillic can be pixel-identical to Latin ones (Cyrillic а vs Latin a), so the domain can impersonate a real brand perfectly."],
    };

    // [tone, icon, badge, title, meaning(count)]
    const HEUR_STATES = {
      clean: ["ok", "✅", "Clean Pattern", "Standard URL Structure", () =>
        "The URL structure looks standard and non-deceptive: a real domain name, a normal length, and none of the disguise tricks phishing links rely on."],
      single: ["warn", "⚠️", "Suspicious Patterns Detected", "1 Suspicious Pattern", () =>
        "One pattern commonly used in phishing links was found. On its own it can be innocent, so weigh it against the reputation, certificate and domain-age results above."],
      multiple: ["err", "🎣", "Suspicious Patterns Detected", "Phishing Patterns Detected", (count) =>
        `${count} patterns typical of phishing links appear together. Combined, they strongly suggest this URL was built to deceive.`],
    };

    // reasons mixes every module's red flags; pick out the URL-pattern findings this card explains
    function heuristicFindings(reasons) {
      return reasons
        .map((reason) => {
          const text = String(reason);
          const split = text.indexOf(":");
          return split === -1
            ? { title: text, detail: "" }
            : { title: text.slice(0, split), detail: text.slice(split + 1).trim() };
        })
        .filter((finding) => finding.title in HEURISTIC_PATTERNS);
    }

    function renderHeuristics(reasons, target) {
      const findings = heuristicFindings(reasons);
      const state = findings.length === 0 ? "clean" : findings.length === 1 ? "single" : "multiple";
      const [tone, icon, badge, title, message] = HEUR_STATES[state];

      $("heur-badge").dataset.tone = tone;
      setText("heur-badge", badge);
      $("heur-verdict").dataset.tone = tone;
      setText("hv-icon", icon);
      setText("hv-title", title);
      setText("hv-body", message(findings.length));
      setText("hv-hint", `Analyzed exactly as entered: ${target}`);

      const list = $("heur-findings");
      list.replaceChildren();
      findings.forEach((finding, index) => {
        const item = document.createElement("li");
        item.className = "finding";
        item.dataset.tone = tone;
        item.style.animationDelay = `${index * 70}ms`;
        const mark = document.createElement("span");
        mark.className = "finding-mark";
        mark.textContent = String(index + 1);
        const body = document.createElement("div");
        body.className = "min-w-0";
        const heading = document.createElement("p");
        heading.className = "finding-title";
        heading.textContent = finding.title;
        const detail = document.createElement("p");
        detail.className = "finding-detail";
        detail.textContent = finding.detail;
        const why = document.createElement("p");
        why.className = "finding-why";
        const whyLabel = document.createElement("span");
        whyLabel.textContent = "Why it's dangerous";
        why.append(whyLabel, HEURISTIC_PATTERNS[finding.title][1]);
        body.append(heading, detail, why);
        item.append(mark, body);
        list.append(item);
      });
      $("heur-findings-wrap").classList.toggle("hidden", findings.length === 0);

      // Every pattern is listed, so a clean result shows exactly what was checked
      const found = new Set(findings.map((finding) => finding.title));
      const checks = $("heur-checks");
      checks.replaceChildren();
      for (const [patternTitle, [label]] of Object.entries(HEURISTIC_PATTERNS)) {
        const hit = found.has(patternTitle);
        const item = document.createElement("li");
        item.className = "check";
        item.dataset.tone = hit ? tone : "ok";
        const mark = document.createElement("span");
        mark.className = "check-mark";
        mark.setAttribute("aria-hidden", "true");
        mark.textContent = hit ? "✗" : "✓";
        item.append(mark, hit ? patternTitle : label);
        checks.append(item);
      }
    }

    const GAUGE_ARC = 376.99;  // 270° of the r = 80 gauge circle
    const GAUGE_CIRCUMFERENCE = 502.65;
    const TOP_REASONS = 6;

    // [tone, title, what the level means for the user]
    const RISK_LEVELS = {
      low: ["ok", "Low Risk", "Few or no threat indicators were found. Normal browsing caution applies."],
      medium: ["warn", "Medium Risk", "Several warning signs were found. Verify the site through a trusted channel before entering any personal information."],
      high: ["high", "High Risk", "Multiple strong phishing or malware indicators. Don't enter credentials or payment details, and treat links to this domain as suspicious."],
      critical: ["crit", "Critical Risk", "This domain shows the hallmarks of an active phishing or malware operation. Do not visit it; block it and report any links pointing to it."],
      unknown: ["muted", "Score Unavailable", "The scan didn't return a valid risk score, so review the individual checks below."],
    };

    function countUp(el, to) {
      if (globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
        el.textContent = String(to);
        return;
      }
      const start = performance.now();
      const step = (now) => {
        const t = Math.min(1, (now - start) / 1100);
        el.textContent = String(Math.round(to * (1 - (1 - t) ** 3)));  // ease-out cubic
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }

    // The scoring engine (scanners/risk_score.py) prefixes reasons: "Clean:" for a clean pass,
    // "Note:" for a check that couldn't run (no points); everything else is a scored red flag
    function reasonItem(reason, tone) {
      const kind = reason.startsWith("Clean:") ? "clean" : reason.startsWith("Note:") ? "note" : "flag";
      const item = document.createElement("li");
      item.className = "reason";
      item.dataset.kind = kind;
      // A red flag is never drawn green, even when the overall level is low
      item.dataset.tone = { clean: "ok", note: "muted", flag: tone === "ok" ? "warn" : tone }[kind];
      const mark = document.createElement("span");
      mark.className = "reason-mark";
      mark.setAttribute("aria-hidden", "true");
      mark.textContent = { clean: "✓", note: "i", flag: "!" }[kind];
      const text = document.createElement("span");
      const note = reason.slice(5).trim();
      text.textContent = kind === "note" ? note.charAt(0).toUpperCase() + note.slice(1) : reason;
      item.append(mark, text);
      return item;
    }

    function renderRisk(data) {
      const valid = Number.isInteger(data.risk_score) && data.risk_level in RISK_LEVELS && data.risk_level !== "unknown";
      const level = valid ? data.risk_level : "unknown";
      const score = valid ? Math.min(100, Math.max(0, data.risk_score)) : 0;
      const [tone, title, meaning] = RISK_LEVELS[level];

      $("risk").dataset.tone = tone;
      $("risk-badge").dataset.tone = tone;
      setText("risk-badge", valid ? `${level} risk` : "Unavailable");
      setText("risk-level", level);
      setText("risk-title", title);
      setText("risk-body", meaning);
      for (const key of ["low", "medium", "high", "critical"]) $(`rl-${key}`).dataset.active = String(key === level);

      // Start from empty so the arc sweeps and the number counts up on every scan
      const arc = $("gauge-arc");
      arc.style.strokeDasharray = `0 ${GAUGE_CIRCUMFERENCE}`;
      requestAnimationFrame(() => requestAnimationFrame(() => {
        arc.style.strokeDasharray = `${(GAUGE_ARC * score) / 100} ${GAUGE_CIRCUMFERENCE}`;
      }));
      if (valid) countUp($("risk-score"), score);
      else setText("risk-score", DASH);

      const reasons = Array.isArray(data.reasons) ? data.reasons.map(String) : [];
      const flags = reasons.filter((reason) => !reason.startsWith("Clean:") && !reason.startsWith("Note:")).length;
      setText("risk-reasons-label", flags ? `Detected red flags (${flags})` : "Findings");
      const top = $("risk-reasons");
      top.replaceChildren(...reasons.slice(0, TOP_REASONS).map((reason) => reasonItem(reason, tone)));
      if (!reasons.length) top.append(reasonItem("Note: no reasons were returned with this score", tone));

      const rest = reasons.slice(TOP_REASONS);
      $("risk-more").classList.toggle("hidden", rest.length === 0);
      setText("risk-more-label", `+ Show ${rest.length} more`);
      $("risk-reasons-more").replaceChildren(...rest.map((reason) => reasonItem(reason, tone)));
    }

    function render(data, ms, target = "") {
      const whois = data.whois || {};
      const [tone, badge] = expiryStatus(whois);
      const left = whois.expires_days_left;

      setText("r-domain", data.domain || DASH);
      setText("r-meta", `scanned ${String(data.scanned_at).replace("T", " ").replace("Z", " UTC")} · ${ms} ms`);
      $("r-badge").dataset.tone = tone;
      setText("r-badge", badge);

      setText("r-created", whois.created);
      setText("r-age", whois.age_days == null ? null : plural(whois.age_days, "day"));
      setText("r-age-sub", whois.age_days == null ? "" : `≈ ${(whois.age_days / 365.25).toFixed(1)} years`);
      setText("r-registrar", whois.registrar);
      setText("r-expires", whois.expires);

      $("c-left").dataset.tone = tone;
      setText("r-left", left == null ? null : left < 0 ? `expired ${plural(left, "day")} ago` : `${plural(left, "day")} remaining`);
      setText("r-left-sub",
        tone === "warn" ? "Under 30 days · typical of short-lived phishing domains"
        : tone === "err" && left != null ? "Registration has lapsed"
        : "");

      renderLifespan(whois, tone);
      renderDns(data.dns || {});
      renderSsl(data.ssl || {});
      renderBlacklist(data.blacklist || {}, data.domain);
      renderHeuristics(Array.isArray(data.reasons) ? data.reasons : [], target || data.domain || "");
      renderRisk(data);
      $("raw").textContent = JSON.stringify(data, null, 2);
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const target = input.value.trim();
      if (!target || button.disabled) return;

      $("alert").classList.add("hidden");
      $("risk").classList.add("hidden");
      $("result").classList.add("hidden");
      $("dns").classList.add("hidden");
      $("ssl").classList.add("hidden");
      $("threat").classList.add("hidden");
      $("heur").classList.add("hidden");
      setLoading(true);
      log("muted", `POST /scan  ${target}`);
      const started = performance.now();

      try {
        const response = await fetch("/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: target }),
        });
        const ms = Math.round(performance.now() - started);
        if (!response.ok) throw new Error(`server responded with ${response.status}`);

        const data = await response.json();
        const whois = data.whois || {};
        const dns = data.dns || {};
        render(data, ms, target);
        $("risk").classList.remove("hidden");
        $("result").classList.remove("hidden");
        $("dns").classList.remove("hidden");
        $("ssl").classList.remove("hidden");
        $("threat").classList.remove("hidden");
        $("heur").classList.remove("hidden");

        const mail = `spf ${dns.spf ? "on" : "off"} / dmarc ${dns.dmarc ? "on" : "off"}`;
        const tls = `tls ${sslDiagnosis(data.ssl || {})[0]}`;
        const blacklist = data.blacklist || {};
        const vt = `vt ${blacklist.error || typeof blacklist.virustotal !== "number" ? "n/a" : blacklist.virustotal}`;
        const patterns = `patterns ${heuristicFindings(Array.isArray(data.reasons) ? data.reasons : []).length}`;
        const level = data.risk_level in RISK_LEVELS ? data.risk_level : "unknown";
        const risk = `risk ${Number.isInteger(data.risk_score) ? data.risk_score : "?"}/100 ${level}`;
        if (whois.error) showAlert(whois.error);
        log(RISK_LEVELS[level][0], `${data.domain} · ${risk} · ${mail} · ${tls} · ${vt} · ${patterns} · ${ms} ms`);
      } catch (err) {
        showAlert(`Request failed: ${err.message}`);
        log("err", `request failed · ${err.message}`);
      } finally {
        setLoading(false);
        input.focus();
      }
    });
  </script>
</body>
</html>
"""
