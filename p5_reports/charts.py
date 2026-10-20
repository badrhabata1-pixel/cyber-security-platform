"""Report charts as base64 PNGs. Uses matplotlib's object API (no pyplot) so concurrent report jobs are safe."""
import base64
import io

import matplotlib

matplotlib.use("Agg")
from matplotlib import ticker
from matplotlib.figure import Figure
from matplotlib.patches import FancyBboxPatch, Rectangle
from matplotlib.transforms import IdentityTransform

DPI = 200
INK, SECONDARY, MUTED, GRID, BASELINE, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"
SERIES = "#2a78d6"
# Fixed status colours (critical / serious / warning) plus a neutral for "low": never reused as series colours
STATUS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#a8a69f"}
RADIUS_PT, GAP_PT = 2.5, 1.5

matplotlib.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7.5, "text.color": INK, "axes.labelcolor": SECONDARY,
                            "xtick.color": MUTED, "ytick.color": SECONDARY})


def _png(fig: Figure) -> str:
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", dpi=DPI, facecolor=SURFACE)
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")


def _clean(ax, grid_axis: str | None = None) -> None:
    for side in ("top", "right", "left", "bottom"):
        ax.spines[side].set_visible(False)
    ax.tick_params(length=0, pad=4)
    if grid_axis:
        ax.grid(axis=grid_axis, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)


def _rounded_bars(ax, positions, values, thickness, colors, horizontal: bool) -> None:
    """Bars with a rounded data end and a square baseline end. Call after the axis limits are final.

    Drawn in pixel space: rounding in data units would stretch with the two axes' different scales.
    """
    fig = ax.figure
    fig.canvas.draw()  # resolves the axes position in pixels
    to_px = ax.transData.transform
    radius = RADIUS_PT / 72 * fig.dpi
    for pos, value, color in zip(positions, values, colors):
        if value <= 0:
            continue
        corners = ((0, pos - thickness / 2), (value, pos + thickness / 2)) if horizontal else ((pos - thickness / 2, 0), (pos + thickness / 2, value))
        (xa, ya), (xb, yb) = to_px(corners[0]), to_px(corners[1])
        (x0, x1), (y0, y1) = sorted((xa, xb)), sorted((ya, yb))
        w, h = x1 - x0, y1 - y0
        r = min(radius, w / 2, h / 2)
        style = {"facecolor": color, "edgecolor": "none", "linewidth": 0, "transform": IdentityTransform()}
        ax.add_patch(FancyBboxPatch((x0, y0), w, h, boxstyle=f"round,pad=0,rounding_size={r}", **style))
        # Square off the baseline end: bars are anchored to the axis, only the data end is rounded
        ax.add_patch(Rectangle((x0, y0), min(r, w), h, **style) if horizontal else Rectangle((x0, y0), w, min(r, h), **style))


def _shorten(text: str, limit: int = 30) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def ranked_bars(pairs: list[tuple[str, int]], width_in: float = 3.3, labels: list[str] | None = None,
                colors: list[str] | None = None, x_max: float | None = None) -> str | None:
    """Horizontal bars, largest first, each value written at the bar tip (so no value axis is needed)."""
    if not pairs or not any(count for _, count in pairs):
        return None
    names = [_shorten(name) for name, _ in pairs]
    values = [count for _, count in pairs]
    fig = Figure(figsize=(width_in, 0.22 * len(pairs) + 0.16), dpi=DPI)
    # Room for the longest name on the left and the tip label on the right, from rough glyph widths
    left = min(0.5, (max(len(n) for n in names) * 7.5 * 0.6 / 72 + 0.12) / width_in)
    tip = (max(len(t) for t in labels) if labels else len(f"{max(values):,}")) * 7.5 * 0.6 / 72 + 0.12
    ax = fig.add_axes((left, 0.02, 0.99 - left, 0.96))
    _clean(ax)
    plot_in = (0.99 - left) * width_in
    ax.set_xlim(0, (x_max or max(values)) * plot_in / max(plot_in - tip, 0.5))
    ax.set_ylim(len(pairs) - 0.5, -0.5)
    ax.set_yticks(range(len(pairs)), names)
    ax.set_xticks([])
    _rounded_bars(ax, range(len(pairs)), values, 0.56, colors or [SERIES] * len(pairs), horizontal=True)
    for i, value in enumerate(values):
        ax.annotate(labels[i] if labels else f"{value:,}", (value, i), xytext=(4, 0), textcoords="offset points",
                    va="center", ha="left", color=INK, fontsize=7.5, annotation_clip=False)
    return _png(fig)


def hourly_columns(hours: list[int], width_in: float = 6.85) -> str | None:
    if not any(hours):
        return None
    fig = Figure(figsize=(width_in, 1.5), dpi=DPI)
    ax = fig.add_axes((0.06, 0.16, 0.93, 0.76))
    _clean(ax, grid_axis="y")
    peak = max(range(24), key=lambda h: hours[h])
    ax.set_xlim(-0.6, 23.6)
    ax.set_ylim(0, hours[peak] * 1.18)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(nbins=4, integer=True))
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda v, _: f"{v / 1000:g}K" if v >= 1000 else f"{v:g}"))
    ax.tick_params(axis="y", colors=MUTED)
    ax.set_xticks(range(0, 24, 3), [f"{h:02d}:00" for h in range(0, 24, 3)])
    ax.axhline(0, color=BASELINE, linewidth=0.8)
    _rounded_bars(ax, range(24), hours, 0.62, [SERIES] * 24, horizontal=False)
    ax.annotate(f"Peak {hours[peak]:,}", (peak, hours[peak]), xytext=(0, 3), textcoords="offset points",
                ha="center", va="bottom", color=INK, fontsize=7.5)
    return _png(fig)


def severity_donut(counts: dict[str, int], width_in: float = 3.3) -> str | None:
    total = sum(counts.values())
    if not total:
        return None
    fig = Figure(figsize=(width_in, 1.75), dpi=DPI)
    ax = fig.add_axes((0.0, 0.04, 0.5, 0.92))
    present = [(s, c) for s, c in counts.items() if c]
    ax.pie([c for _, c in present], colors=[STATUS[s] for s, _ in present], startangle=90, counterclock=False,
           wedgeprops={"width": 0.3, "edgecolor": SURFACE, "linewidth": GAP_PT})
    ax.set_aspect("equal")
    ax.text(0, 0.07, f"{total}", ha="center", va="center", fontsize=15, fontweight="bold", color=INK)
    ax.text(0, -0.2, "alerts", ha="center", va="center", fontsize=7.5, color=SECONDARY)
    # Legend with names and counts, so severity never relies on colour alone
    for i, (severity, count) in enumerate(counts.items()):
        y = 0.78 - i * 0.19
        fig.add_artist(Rectangle((0.56, y - 0.035), 0.035, 0.07, transform=fig.transFigure, facecolor=STATUS[severity], edgecolor="none"))
        fig.text(0.62, y, severity.capitalize(), va="center", ha="left", fontsize=7.5, color=SECONDARY)
        fig.text(0.95, y, f"{count}", va="center", ha="right", fontsize=7.5, color=INK, fontweight="bold")
    return _png(fig)


def domain_risk(rows: list[dict], width_in: float = 6.85) -> str | None:
    rows = rows[:10]
    if not rows:
        return None
    pairs = [(row["domain"], row["score"]) for row in rows]
    labels = [f"{row['score']} · {row['level'].capitalize()}" for row in rows]
    return ranked_bars(pairs, width_in=width_in, labels=labels, colors=[STATUS.get(row["level"], MUTED) for row in rows], x_max=100)


def build_charts(ctx: dict) -> dict:
    logs, alerts, domains = ctx["logs"], ctx["alerts"], ctx["domains"]
    return {
        "top_ips": ranked_bars(logs["top_ips"]) if logs else None,
        "top_countries": ranked_bars(logs["top_countries"]) if logs else None,
        "by_hour": hourly_columns(logs["by_hour"]) if logs else None,
        "severity": severity_donut(alerts["by_severity"]) if alerts else None,
        "domains": domain_risk(domains["rows"]) if domains else None,
    }
