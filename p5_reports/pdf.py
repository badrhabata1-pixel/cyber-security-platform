"""Renders the report context into a PDF: Jinja2 template -> HTML -> xhtml2pdf."""
import base64
import io
import os
import threading
from functools import lru_cache
from pathlib import Path

import matplotlib
from jinja2 import Environment, FileSystemLoader, select_autoescape
from matplotlib.figure import Figure
from matplotlib.patches import Circle, Rectangle
from xhtml2pdf import pisa
from xhtml2pdf.config.resources import ResourceAccessPolicy

import charts
from report_data import SECTIONS

TEMPLATES = Path(__file__).with_name("templates")
# DejaVu ships with matplotlib, so every machine has it, and it covers Cyrillic/Greek look-alike domains
FONT_DIR = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
FONTS = {"font:regular": FONT_DIR / "DejaVuSans.ttf", "font:bold": FONT_DIR / "DejaVuSans-Bold.ttf"}
# The HTML carries text from other services (domains, alert descriptions): autoescape it, and let the
# renderer read nothing but our fonts - no network, no other local files (SSRF / file disclosure).
POLICY = ResourceAccessPolicy.server(base_dir=None, extra_roots=(FONT_DIR,), allow_remote=False)
STATUS_COLORS = {**charts.STATUS, "good": "#0ca30c"}
PRIORITY_COLORS = {"Immediate": charts.STATUS["critical"], "High": charts.STATUS["high"], "Medium": charts.STATUS["medium"], "Low": charts.STATUS["low"]}
NAVY, BLUE = "#0d366b", "#2a78d6"

env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
env.filters["num"] = lambda value: f"{value:,}" if isinstance(value, int) else value
_render_lock = threading.Lock()  # reportlab keeps global font state


@lru_cache(maxsize=1)
def cover_background() -> str:
    """A4 cover art: navy band with faint radar rings and a blue accent rule, drawn once per process."""
    width, height, band = 8.27, 11.69, 11.69 * 0.43
    fig = Figure(figsize=(width, height), dpi=110)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, width)
    ax.set_ylim(0, height)
    ax.axis("off")
    panel = Rectangle((0, band), width, height - band, facecolor=NAVY, edgecolor="none")
    ax.add_patch(panel)
    for radius in [0.5 + 0.55 * i for i in range(12)]:
        ring = Circle((6.9, band + 1.3), radius, fill=False, edgecolor="white", alpha=0.07, linewidth=0.9)
        ax.add_patch(ring)
        ring.set_clip_path(panel)
    ax.add_patch(Rectangle((0, band - 0.06), width, 0.06, facecolor=BLUE, edgecolor="none"))
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", facecolor="white")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def _link_callback(uri: str, _rel) -> str | None:
    font = FONTS.get(uri)
    return str(font) if font else None


def _image(uri: str | None, chart_width_in: float) -> dict | None:
    """Template-ready <img>: xhtml2pdf sizes images in CSS px (1/96 in)."""
    if not uri:
        return None
    raw = base64.b64decode(uri.split(",", 1)[1])
    width_px, height_px = int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")  # PNG IHDR
    return {"src": uri, "width": round(chart_width_in * 96), "height": round(chart_width_in * 96 * height_px / width_px)}


def render_pdf(ctx: dict, path: Path) -> None:
    images = charts.build_charts(ctx)
    full, half = 6.85, 3.3
    numbers = {name: i + 1 for i, name in enumerate(n for n in SECTIONS if n in ctx["wanted"])}
    html = env.get_template("report.html").render(
        **ctx, numbers=numbers, cover=cover_background(), status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS,
        charts={name: _image(uri, full if name in ("by_hour", "domains") else half) for name, uri in images.items()},
    )
    temporary = path.with_suffix(".tmp")
    with _render_lock, open(temporary, "wb") as output:
        result = pisa.CreatePDF(html, dest=output, link_callback=_link_callback, resource_policy=POLICY, encoding="utf-8")
    if result.err:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"PDF rendering failed with {result.err} error(s)")
    os.replace(temporary, path)  # a half-written PDF is never served
