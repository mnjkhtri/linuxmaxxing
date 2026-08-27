from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from db import Database

app = FastAPI(title="Twitter Intelligence")
HTML = (Path(__file__).parent / "dashboard.html").read_text()


def tc(m):
    t = m.lower().replace(" ", "_")
    return f"t{t}" if t in ("crypto", "equities", "macro", "options", "rates_fx") else "tother"


def tag_html(items, cls_fn=None):
    if not items:
        return "", ""
    title = ", ".join(items)
    parts = []
    for i, v in enumerate(items):
        if i >= 3:
            parts.append(f'<span class="plus">+{len(items)-3}</span>')
            break
        c = f" {cls_fn(v)}" if cls_fn else ""
        parts.append(f'<span class="tag{c}">{v}</span>')
    return "".join(parts), title


@app.get("/", response_class=HTMLResponse)
def index():
    db = Database()
    users = db.get_users()
    states = db.get_all_scrape_states()

    total = len(users)
    scraped = 0; tweets_total = 0; tax_done = 0; latest = ""
    rows = ""

    for h in users:
        s = states.get(h)
        t = db.get_taxonomy(h)

        if s:
            scraped += 1
            tweets_total += s["tweet_count"]
            if s["taxonomy_updated"]:
                tax_done += 1
            if s["scraped_at"] > latest:
                latest = s["scraped_at"]

        if s and not s["taxonomy_updated"]:
            delta_cell = f'<span class="yel">{s["tweet_count"]}</span>'
        elif s:
            delta_cell = '<span class="grn">0</span>'
        else:
            delta_cell = '<span class="gry">-</span>'

        scraped_cell = f'<span class="grn" title="{s["scraped_at"]}">{s["scraped_at"][:10]}</span>' if s else '<span class="gry">-</span>'

        if t:
            tax_cell = f'<span class="grn">{t.get("scrape_data_tweet_count", "?")}</span>'
        elif s:
            tax_cell = '<span class="gry">0</span>'
        else:
            tax_cell = '<span class="gry">-</span>'

        if t:
            roles_d, roles_t = tag_html(t.get("roles", []))
            mkts_d, mkts_t = tag_html(t.get("markets", []), tc)
            topics_d, topics_t = tag_html(t.get("topics", []))
            signal = t.get("signal", "")
            horizon = t.get("horizon", "")
            use = t.get("use", "")
            assets_d, assets_t = tag_html(t.get("assets", []))
            flags_d, flags_t = tag_html(t.get("flags", []))
            q = t.get("quality", {})
            qual = qual_t = ""
            if q:
                s_s = q.get("specificity", "?"); o_s = q.get("originality", "?")
                t_s = q.get("timeliness", "?"); n_s = q.get("noise", "?"); ov = q.get("overall", "?")
                qual = f"S{s_s} O{o_s} T{t_s} N{n_s} Ov{ov}"
                qual_t = f"Specificity:{s_s} Originality:{o_s} Timeliness:{t_s} Noise:{n_s} Overall:{ov}"
            notes = t.get("notes", "")
            notes_d = notes[:80] + ("..." if len(notes) > 80 else "") if notes else ""
            notes_t = notes
        else:
            roles_d = mkts_d = topics_d = signal = horizon = use = assets_d = flags_d = qual = notes_d = ""
            roles_t = mkts_t = topics_t = assets_t = flags_t = qual_t = notes_t = ""

        def dtt(content, tip):
            return f'<td data-tip="{tip}"><span>{content}</span></td>' if tip else f"<td><span>{content}</span></td>"

        rows += "<tr>"
        rows += f'<td class="handle"><a href="https://x.com/{h}" target="_blank" style="color:inherit;text-decoration:none">@{h}</a></td>'
        rows += f"<td><span>{delta_cell}</span></td>"
        rows += f"<td><span>{scraped_cell}</span></td>"
        rows += f"<td><span>{tax_cell}</span></td>"
        rows += dtt(roles_d, roles_t)
        rows += dtt(mkts_d, mkts_t)
        rows += dtt(topics_d, topics_t)
        rows += dtt(signal, signal)
        rows += dtt(horizon, horizon)
        rows += dtt(use, use)
        rows += dtt(assets_d, assets_t)
        rows += dtt(flags_d, flags_t)
        rows += dtt(f'<span class="qual">{qual}</span>', qual_t)
        rows += dtt(notes_d, notes_t)
        rows += "</tr>\n"

    html = HTML.replace("__ROWS__", rows)
    html = html.replace("__SCRAPED__", str(scraped))
    html = html.replace("__TOTAL__", str(total))
    html = html.replace("__TWEETS__", str(tweets_total))
    html = html.replace("__TAX_DONE__", str(tax_done))
    html = html.replace("__LATEST__", latest[:10] if latest else "-")
    return HTMLResponse(html)
