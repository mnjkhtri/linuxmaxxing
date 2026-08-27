# Agent Context

## Project

Twitter/X intelligence scraper for finance, trading, investing, crypto, and macro accounts. The project has one unified user universe; there are no list-level groups.

## Files

| Path | Purpose |
|------|---------|
| `scraper.py` | Login and scrape entrypoint |
| `db.py` | SQLite database layer (schema, migrations, CRUD) |
| `data/twitter.db` | SQLite database (scrape state, tweets, user universe, taxonomy) |
| `taxonomy/template.json` | Taxonomy schema/reference |
| `cookies.json` | X session cookies |
| | The `users` table in `data/twitter.db` is the sole source of the user universe |



## Database

Use `db.py`'s `Database` class for all reads/writes:

```python
from db import Database
db = Database()
```

### Key methods for agents

| Method | Purpose |
|--------|---------|
| `db.get_users()` | List all tracked handles |
| `db.add_users(["handle1", "handle2"])` | Add new handles to the user universe |
| `db.get_scrape_data(handle)` → dict with `scraped_at`, `tweet_count`, `tweets` | Latest scrape for one user |
| `db.get_taxonomy(handle)` → dict or None | Taxonomy record for one user |
| `db.save_taxonomy(handle, dict)` | Write taxonomy record |
| `db.set_taxonomy_updated(handle, True)` | Mark taxonomy as updated in scrape_state |

## Operator Commands

When the user says `run the dashboard`, start the web server: `setsid ./venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000 > /tmp/uvicorn.log 2>&1 &` and tell the user the URL is `http://localhost:8000/`.

When the user says `update me on data` or `status`, run `python status.py` with the project venv.

When the user says `scrape X users`, run `python scraper.py --batch X --delay Y` with the project venv if needed. If the user does not specify a delay, use `--delay 10`. The `users` table in the DB is the universe; users missing from `scrape_state` are scraped first; users with `taxonomy_updated: false` are skipped; eligible users are weighted by age of `scrape_data_used_from` multiplied by a confidence factor (`100 / scrape_data_tweet_count`) so users with thinner taxonomies are prioritized. Any new scrape sets `taxonomy_updated` to `false`.

When the user says `update taxonomy for X users`, sample users where `taxonomy_updated` is `false`, weighted by age of `scraped_at` multiplied by a confidence factor (`100 / scrape_data_tweet_count` from any existing taxonomy, default 2x if no taxonomy yet). Then spawn agents for the sampled users. Each agent must:

1. Read scrape data via `db.get_scrape_data(handle)` — **NEVER use Playwright or scrape Twitter. Only read from the database.**
2. If the user has 0 tweets, save a minimal taxonomy with `flags: ["thin_sample"]` and notes saying "no tweets available", then mark done.
3. If no existing taxonomy, read `taxonomy/template.json` for the schema
4. Write taxonomy via `db.save_taxonomy(handle, taxonomy_dict)`, setting `scrape_data_used_from` and `scrape_data_tweet_count` from the scrape data
5. Mark taxonomy done via `db.set_taxonomy_updated(handle, True)`

**CRITICAL: Do NOT write any .py files, do NOT use Playwright, do NOT scrape Twitter/X. Use ONLY `db.get_scrape_data()` and `db.save_taxonomy()`.**

## Notes

- Use `./venv/bin/python scraper.py` if system Python lacks Playwright.
- Do not reintroduce AB1/Jon/list grouping.
- All scrapes are saved regardless of tweet count; low-count users are naturally prioritized for re-scraping by the confidence factor.
- The web dashboard is at `api.py`. Run with `./venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000` and open `http://localhost:8000/`.
- To add new users, call `db.add_users(["handle1", "handle2"])` or they can be added before running a scrape.
