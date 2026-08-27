import asyncio
import json
import argparse
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

from db import Database, now_iso, DATA_DIR

COOKIES_FILE    = Path(__file__).parent / "cookies.json"
TWEETS_PER_USER = 100


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def weighted_sample_without_replacement(items: list[tuple[str, float, str]], count: int) -> list[tuple[str, str]]:
    selected: list[tuple[str, str]] = []
    pool = items[:]
    while pool and (not count or len(selected) < count):
        total = sum(weight for _, weight, _ in pool)
        if total <= 0:
            index = random.randrange(len(pool))
        else:
            pick = random.uniform(0, total)
            upto = 0.0
            index = 0
            for i, (_, weight, _) in enumerate(pool):
                upto += weight
                if upto >= pick:
                    index = i
                    break
        handle, _, reason = pool.pop(index)
        selected.append((handle, reason))
    return selected


def select_users_to_scrape(db: Database, batch: int) -> list[tuple[str, str]]:
    users = db.get_users()
    scrape_state = db.get_all_scrape_states()

    missing_state = [h for h in users if h not in scrape_state]
    if missing_state:
        selected = missing_state[:batch] if batch else missing_state
        return [(h, "missing from scrape_state") for h in selected]

    now = datetime.now(timezone.utc)
    weighted: list[tuple[str, float, str]] = []
    for handle in users:
        state = scrape_state.get(handle, {})
        if not state.get("taxonomy_updated"):
            continue
        taxonomy = db.get_taxonomy(handle)
        if not taxonomy:
            continue
        used_at = parse_iso(taxonomy.get("scrape_data_used_from"))
        if not used_at:
            continue
        age_hours = max((now - used_at).total_seconds() / 3600, 0.0)
        tweet_count = taxonomy.get("scrape_data_tweet_count", 50)
        confidence_factor = 100 / max(tweet_count, 1)
        weight = (age_hours + 1.0) * confidence_factor
        weighted.append((handle, weight, f"{age_hours:.1f}h old, {tweet_count}t used"))

    return weighted_sample_without_replacement(weighted, batch)


def save_user_session(db: Database, handle: str, tweets: list[dict]) -> str:
    scrape_ts = now_iso()
    db.save_tweets(handle, scrape_ts, len(tweets), tweets)
    return scrape_ts


async def new_browser(p, headless: bool):
    browser = await p.chromium.launch(
        headless=headless,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled",
            "--disable-automation",
            "--disable-web-security",
            "--disable-features=ChromeWhatsNewUI,ChromeLabs",
            "--no-first-run",
            "--no-default-browser-check",
        ],
    )
    context = await browser.new_context(
        viewport={"width": 1280, "height": 900},
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        locale="en-US",
        timezone_id="America/New_York",
    )
    await context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        window.chrome = { runtime: {} };
    """)
    return browser, context


async def login():
    async with async_playwright() as p:
        browser, context = await new_browser(p, headless=False)
        page = await context.new_page()

        try:
            await page.goto("https://x.com/login", wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            print(f"[!] nav: {e}")

        print("[*] Log in to X in the browser...")
        elapsed = 0
        while elapsed < 300:
            try:
                await page.wait_for_timeout(3000)
                elapsed += 3
                if await page.query_selector('[data-testid="primaryColumn"]'):
                    print("[+] Logged in")
                    break
            except Exception:
                try:
                    page = await context.new_page()
                    await page.goto("https://x.com/login", wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    pass
                elapsed += 3
        else:
            print("[!] Timed out")
            await browser.close()
            return

        COOKIES_FILE.write_text(json.dumps(await context.cookies(), indent=2))
        print("[+] Cookies saved")
        await browser.close()


async def extract_tweets(page, handle: str) -> list[dict]:
    return await page.evaluate(f"""() => {{
        const handle = {json.dumps(handle.lower())};
        const results = [];
        for (const article of document.querySelectorAll('article[data-testid="tweet"]')) {{
            try {{
                const timeEl  = article.querySelector('time');
                if (!timeEl) continue;
                const linkEl  = timeEl.closest('a');
                const href    = linkEl ? linkEl.getAttribute('href') : '';
                if (!href || !href.toLowerCase().includes('/' + handle + '/')) continue;
                const url       = 'https://x.com' + href;
                const idMatch   = href.match(/\\/status\\/(\\d+)/);
                if (!idMatch) continue;
                const tweet_id  = idMatch[1];
                const textEl    = article.querySelector('[data-testid="tweetText"]');
                const text      = textEl ? textEl.innerText.trim() : '';
                const timestamp = timeEl.getAttribute('datetime') || '';
                const count = testid => {{
                    const el  = article.querySelector('[data-testid="' + testid + '"]');
                    if (!el) return 0;
                    const raw = el.innerText.trim().toUpperCase().replace(/,/g, '');
                    if (!raw) return 0;
                    if (raw.endsWith('K')) return Math.round(parseFloat(raw) * 1000);
                    if (raw.endsWith('M')) return Math.round(parseFloat(raw) * 1000000);
                    return parseInt(raw) || 0;
                }};
                results.push({{ tweet_id, text, timestamp, url,
                    likes: count('like'), retweets: count('retweet'), replies: count('reply') }});
            }} catch(e) {{ continue; }}
        }}
        return results;
    }}""")


async def scrape_user(page, handle: str):
    """Returns tweets collected from the user's Posts tab."""
    try:
        await page.goto(f"https://x.com/{handle}", wait_until="domcontentloaded", timeout=20000)
        await page.wait_for_selector('article[data-testid="tweet"]', timeout=25000)
    except Exception:
        return []

    seen_ids      : set[str]   = set()
    tweets        : list[dict] = []
    no_new_streak = 0

    while True:
        prev = len(tweets)
        for t in await extract_tweets(page, handle):
            if t["tweet_id"] not in seen_ids:
                seen_ids.add(t["tweet_id"])
                tweets.append(t)

        no_new_streak = 0 if len(tweets) > prev else no_new_streak + 1

        if no_new_streak >= 10 or len(tweets) >= TWEETS_PER_USER:
            break

        await page.evaluate("window.scrollBy(0, 1500)")
        await page.wait_for_timeout(2000)

    return tweets[:TWEETS_PER_USER]


async def scrape(delay: int, headless: bool, batch: int, db: Database):
    selected_users = select_users_to_scrape(db, batch)

    if not selected_users:
        print("[+] No users selected")
        return

    remaining = [handle for handle, _ in selected_users]
    print(f"[+] {len(remaining)} users | {now_iso()}")

    if not COOKIES_FILE.exists():
        print("[!] cookies.json not found. Run --login first")
        return

    shared_cookies = json.loads(COOKIES_FILE.read_text())

    for i, handle in enumerate(remaining, 1):
        tweets = []
        for attempt in range(3):
            try:
                async with async_playwright() as p:
                    async with asyncio.timeout(120):
                        browser, context = await new_browser(p, headless)
                        await context.add_cookies(shared_cookies)
                        page = await context.new_page()
                        await page.goto("https://x.com/home", wait_until="domcontentloaded", timeout=20000)
                        await page.wait_for_timeout(4000)
                        tweets = await scrape_user(page, handle)
                        await browser.close()
                break
            except BaseException as e:
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                print(f"[{i}/{len(remaining)}] retry {attempt+1} @{handle}: {type(e).__name__}")
                tweets = []
                continue

        scrape_ts = save_user_session(db, handle, tweets)
        label = f" {scrape_ts}" if len(tweets) >= 50 else " review"
        print(f"[{i}/{len(remaining)}] @{handle} {len(tweets)}t{label}")

        if i < len(remaining):
            wait = random.uniform(delay, delay * 3)
            await asyncio.sleep(wait)

    print(f"[+] Done | {DATA_DIR}/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--login",       action="store_true",       help="Open browser to log in and save cookies")
    parser.add_argument("--batch",       type=int,                  help="Number of users to scrape")
    parser.add_argument("--delay",       type=int,                  help="Base seconds between users")
    parser.add_argument("--no-headless", action="store_true",       help="Show browser window")
    args = parser.parse_args()

    db = Database()

    if args.login:
        asyncio.run(login())
    else:
        if args.batch is None or args.batch <= 0:
            parser.error("--batch is required and must be greater than 0 when scraping")
        if args.delay is None or args.delay <= 0:
            parser.error("--delay is required and must be greater than 0 when scraping")
        asyncio.run(scrape(
            delay=args.delay,
            headless=not args.no_headless,
            batch=args.batch,
            db=db,
        ))
