from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parent
FIGURES = ROOT / "figures"

PALETTE = {
    "baseline": "#9AA0A6",
    "paper": "#4C78A8",
    "ht": "#2A9D77",
    "l1": "#D95F5F",
    "func1": "#59A14F",
    "func2": "#7B6FB0",
    "metric2": "#2A9D77",
}

GROUPED_BAR_WIDTH = 0.24
SINGLE_BAR_WIDTH = 0.52


def set_chart_style():
    matplotlib.rcParams.update(
        {
            "font.size": 11,
            "font.family": "serif",
            "axes.grid": True,
            "grid.alpha": 0.22,
            "grid.linestyle": "--",
            "grid.linewidth": 0.7,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )


def add_bar_labels(ax, bars, color, decimals=0, offset=0.8):
    for bar in bars:
        height = bar.get_height()
        label = f"{height:.{decimals}f}"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + offset,
            label,
            ha="center",
            va="bottom",
            fontsize=9,
            color=color,
        )


def style_bar(bar, facecolor):
    bar.set_facecolor(facecolor)
    bar.set_edgecolor("#FFFFFF")
    bar.set_linewidth(0.8)


def save_ept_latency():
    set_chart_style()
    categories = ["L1 VM", "L2 baseline", "L2 + HT"]
    avg = [5.02, 22.33, 8.31]
    p99 = [9.48, 52.16, 17.72]
    x = np.arange(len(categories))
    width = 0.22

    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    bars_avg = ax.bar(
        x - width / 2,
        avg,
        width,
        label="Average",
    )
    bars_p99 = ax.bar(
        x + width / 2,
        p99,
        width,
        label="99p",
    )
    for bar in bars_avg:
        style_bar(bar, PALETTE["paper"])
    for bar in bars_p99:
        style_bar(bar, PALETTE["metric2"])

    add_bar_labels(ax, bars_avg, "#333333", decimals=2, offset=1.0)
    add_bar_labels(ax, bars_p99, "#333333", decimals=2, offset=1.0)
    ax.set_title("EPT Fault Latency")
    ax.set_ylabel("Latency [us]")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 60)
    ax.legend(frameon=True, loc="upper left")
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "ept_latency_reproduction.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_nginx_throughput():
    set_chart_style()
    categories = ["Nested-VirtIO", "HT (plain)", "HT +\nrate_limiter", "HT +\ntcp_top"]
    colors = [PALETTE["baseline"], PALETTE["ht"], PALETTE["func1"], PALETTE["func2"]]
    nginx_values = [1000.75, 1812.38, 1641.41, 1706.01]
    redis_values = [436.32, 443.14, 445.98, 446.49]
    x = np.array([0.0, 0.82, 1.64, 2.46])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.0, 4.4), sharex=True)

    app_bar_width = 0.35
    bars1 = ax1.bar(x, nginx_values, width=app_bar_width, color=colors, edgecolor="white", linewidth=0.8)
    add_bar_labels(ax1, bars1, "#333333", decimals=0, offset=28)
    ax1.set_title("(a) NGINX, 64 MiB file")
    ax1.set_ylabel("Throughput [MiB/s]")
    ax1.set_xticks(x)
    ax1.set_xticklabels(categories)
    ax1.set_ylim(0, 2050)
    ax1.grid(axis="y")
    ax1.grid(axis="x", visible=False)

    bars2 = ax2.bar(x, redis_values, width=app_bar_width, color=colors, edgecolor="white", linewidth=0.8)
    add_bar_labels(ax2, bars2, "#333333", decimals=0, offset=6)
    ax2.set_title("(b) Redis GET")
    ax2.set_ylabel("Throughput [MiB/s]")
    ax2.set_xticks(x)
    ax2.set_xticklabels(categories)
    ax2.set_ylim(0, 500)
    ax2.grid(axis="y")
    ax2.grid(axis="x", visible=False)

    fig.suptitle("Application Throughput")
    fig.tight_layout()
    fig.savefig(FIGURES / "nginx_largefile_throughput.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_profiling_memcached():
    set_chart_style()
    qps = [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]
    no_prof = [223.9, 203.3, 228.4, 227.8, 243.3, 243.5, 256.6, 248.2, 265.9, 258.5]
    ht_1k = [212.8, 233.9, 229.8, 245.0, 246.0, 249.6, 250.2, 261.0, 265.2, 275.0]
    l1_1k = [272.3, 289.5, 286.2, 297.7, 299.4, 299.3, 316.0, 323.3, 332.5, 353.1]
    ht_4k = [225.1, 232.4, 205.6, 246.9, 249.3, 294.6, 317.7, 341.7, 366.1, 396.0]
    l1_4k = [200.7, 225.6, 239.2, 247.0, 247.5, 283.1, 325.2, 332.8, 360.6, 386.3]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5), sharey=False)
    for ax, ht, l1, title, ymax in [
        (ax1, ht_1k, l1_1k, "(a) 1000 Hz", 400),
        (ax2, ht_4k, l1_4k, "(b) 4000 Hz", 430),
    ]:
        ax.plot(qps, no_prof, color=PALETTE["baseline"], marker="o", ms=4.5, lw=1.7, label="No profiling")
        ax.plot(qps, ht, color=PALETTE["ht"], marker="^", ms=5, lw=1.7, label="Profiling w/ HyperTurtle")
        ax.plot(qps, l1, color=PALETTE["l1"], marker="v", ms=5, lw=1.7, label="Profiling from L1")
        ax.set_xlabel("Throughput [Kqueries/sec]")
        ax.set_ylabel("p99 read latency [us]")
        ax.set_title(title)
        ax.set_xlim(0, 22)
        ax.set_ylim(150, ymax)
        ax.grid(True)

    ax1.legend(fontsize=9, frameon=True)
    fig.suptitle("Figure 14: p99 latencies of Memcached get requests during profiling", fontsize=13)
    fig.tight_layout()
    fig.savefig(FIGURES / "profiling_memcached_1khz.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_memcached_firewall_curve():
    set_chart_style()

    nested_x = [7.76988, 15.56725, 25.30436, 30.24584, 30.77663, 28.75861, 27.57099, 28.15489, 27.33795, 27.90586, 33.19698]
    nested_y = [0.178, 0.197, 0.273, 0.504, 0.747, 2.771, 3.863, 4.605, 4.808, 4.842, 5.065]

    ht_fw_x = [12.72799, 22.86144, 38.57256, 38.07211, 43.22567, 42.22893, 40.83696, 36.67160, 40.97141, 36.75457, 36.89789]
    ht_fw_y = [0.095, 0.121, 0.163, 0.460, 0.612, 0.932, 1.565, 2.309, 2.646, 3.504, 4.683]

    plain_ht_x = [11.35411, 25.79989, 39.04639, 37.44930, 38.28302, 41.09642, 41.80163, 36.27005, 36.17748, 36.40476, 36.79213]
    plain_ht_y = [0.101, 0.102, 0.163, 0.464, 0.757, 0.969, 1.525, 2.340, 2.941, 3.542, 4.706]

    fig, ax = plt.subplots(figsize=(6.8, 4.8))
    ax.plot(nested_x, nested_y, color=PALETTE["l1"], marker="o", ms=5, lw=1.7, label="Nested-VirtIO + Firewall")
    ax.plot(ht_fw_x, ht_fw_y, color=PALETTE["ht"], marker="^", ms=5, lw=1.7, label="HT + Firewall")
    ax.plot(plain_ht_x, plain_ht_y, color=PALETTE["paper"], marker="s", ms=4.8, lw=1.7, linestyle="--", label="Plain HT (no firewall)")
    ax.axhline(0.5, color="#333333", linestyle=":", lw=1.1, label="0.5 ms SLA target")
    ax.set_title("Memcached Throughput vs p99 Latency")
    ax.set_xlabel("Throughput [Kops/s]")
    ax.set_ylabel("99th-percentile latency [ms]")
    ax.set_xlim(0, 50)
    ax.set_ylim(0, 1.0)
    ax.grid(True)
    ax.legend(frameon=True, fontsize=9, loc="upper left")
    fig.tight_layout()
    fig.savefig(FIGURES / "memcached_firewall_curve.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_profiling_sampling_latency():
    set_chart_style()
    configs = ["L0->L1\n(optimal)", "L1->L1", "L1->L2", "HT->L2"]
    paper = [5.66, 25.63, 60.68, 8.49]
    ours = [4.93, None, 75.0, 7.02]
    x = np.arange(len(configs))

    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bars_paper = ax.bar(
        x - GROUPED_BAR_WIDTH / 2,
        paper,
        GROUPED_BAR_WIDTH,
        label="Paper reported",
    )
    ours_plot = [value if value is not None else 0 for value in ours]
    bars_ours = ax.bar(
        x + GROUPED_BAR_WIDTH / 2,
        ours_plot,
        GROUPED_BAR_WIDTH,
        label="Our measurement",
    )
    for bar in bars_paper:
        style_bar(bar, PALETTE["paper"])
    for bar, value in zip(bars_ours, ours):
        if value is None:
            bar.set_facecolor("none")
            bar.set_edgecolor("none")
        else:
            style_bar(bar, PALETTE["ht"])

    add_bar_labels(ax, bars_paper, "#333333", decimals=1, offset=1.0)
    for bar, value in zip(bars_ours, ours):
        if value is None:
            continue
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 1.0,
            f"{value:.1f}",
            ha="center",
            va="bottom",
            fontsize=9,
            color="#333333",
        )

    ax.set_title("Table 4 / Figure 9(b): Profiler sampling event latency")
    ax.set_ylabel("Latency [us]")
    ax.set_xticks(x)
    ax.set_xticklabels(configs)
    ax.set_ylim(0, 85)
    ax.legend(frameon=True)
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "profiling_sampling_latency.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_gups():
    set_chart_style()
    modes = ["Kata baseline", "Kata + HT @ 1 kHz", "Kata + L1 @ 1 kHz"]
    values = [310.01, 310.44, 310.45]
    x = np.arange(len(modes))

    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bars = ax.bar(
        x,
        values,
        width=SINGLE_BAR_WIDTH,
    )
    fills = [PALETTE["baseline"], PALETTE["ht"], PALETTE["l1"]]
    for bar, fill in zip(bars, fills):
        style_bar(bar, fill)
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.03,
            f"{value:.2f}",
            ha="center",
            va="bottom",
            fontsize=9,
            color="#333333",
        )
    ax.set_title("4 MiB GUPS proxy under profiling")
    ax.set_ylabel("Throughput [Mops]")
    ax.set_xticks(x)
    ax.set_xticklabels(modes, rotation=12, ha="right")
    ax.set_ylim(309.5, 311.0)
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "profiling_gups_proxy_output.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def save_kata_startup():
    set_chart_style()
    images = ["alpine", "ubuntu", "java", "js", "python", "pd"]
    baseline = [2.88, 2.77, 2.76, 2.65, 2.68, 2.67]
    ht       = [2.072, 1.857, 1.949, 2.127, 1.893, 1.818]
    x = np.arange(len(images))
    width = 0.32

    fig, ax = plt.subplots(figsize=(8.0, 4.4))
    bars_base = ax.bar(x - width / 2, baseline, width, label="Baseline")
    bars_ht   = ax.bar(x + width / 2, ht,       width, label="HyperTurtle")
    for bar in bars_base:
        style_bar(bar, PALETTE["baseline"])
    for bar in bars_ht:
        style_bar(bar, PALETTE["ht"])
    add_bar_labels(ax, bars_base, "#333333", decimals=2, offset=0.04)
    add_bar_labels(ax, bars_ht,   "#333333", decimals=2, offset=0.04)
    ax.set_title("Kata Container Startup Time")
    ax.set_ylabel("Startup time [s]")
    ax.set_xticks(x)
    ax.set_xticklabels(images)
    ax.set_ylim(0, 3.4)
    ax.legend(frameon=True)
    ax.grid(axis="y")
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "kata_startup_comparison.png", bbox_inches="tight", dpi=300)
    plt.close(fig)


def main():
    FIGURES.mkdir(parents=True, exist_ok=True)
    save_ept_latency()
    save_kata_startup()
    save_nginx_throughput()
    save_memcached_firewall_curve()
    save_profiling_memcached()
    save_profiling_sampling_latency()
    save_gups()


if __name__ == "__main__":
    main()
