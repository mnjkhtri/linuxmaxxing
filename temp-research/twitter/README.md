# Twitter Intelligence Scraper

Tracks a unified set of Twitter/X users, stores the latest scrape per user, and maintains a compact taxonomy per user for recency-weighted rescraping.

## Structure

```text
data/
  state.json              # scrape state indexed by handle
  users/
    {handle}.json          # latest raw scrape for that handle

taxonomy/
  template.json            # taxonomy schema/reference
  users/
    {handle}.json          # taxonomy for that handle

users.json                 # tracked user universe
cookies.json               # X session cookies
scraper.py                 # scraper entrypoint
```

## Commands

Ask the assistant:

```text
scrape X users
```

The assistant runs `python scraper.py --batch X --delay Y`. `users.json` is the universe; users missing from `data/state.json` are scraped first; users with `taxonomy_updated: false` are skipped; eligible users are sampled by age of `taxonomy/users/{handle}.json.scrape_data_used_from`. A new scrape overwrites `data/users/{handle}.json` and sets `taxonomy_updated` to `false`.

```text
update taxonomy for X users
```

The assistant samples users where `data/state.json[handle].taxonomy_updated` is `false`, weighted by age of `data/state.json[handle].scraped_at` so older pending scrapes are more likely to be processed. It then spawns agents for the sampled users. Each agent reads `data/users/{handle}.json`; if `taxonomy/users/{handle}.json` does not exist, it uses `taxonomy/template.json` to create the first taxonomy record. The agent then writes `taxonomy/users/{handle}.json`, sets `scrape_data_used_from` to `data/state.json[handle].scraped_at`, and marks `taxonomy_updated` as `true`.

## Scraper Usage

```bash
python scraper.py --login       # refresh cookies
python scraper.py --batch 50 --delay 25    # scrape 50 selected users
```

## Scrape State

`data/state.json`:

```json
{
  "adambliv": {
    "scraped_at": "2026-05-09T21:07:50Z",
    "tweet_count": 100,
    "taxonomy_updated": false
  }
}
```

`tweet_count` is the number of tweets in the latest scrape only.

## Raw Tweet Data

Each `data/users/{handle}.json` contains:

```json
{
  "scraped_at": "...",
  "tweet_count": 100,
  "tweets": [
    {
      "tweet_id": "...",
      "text": "...",
      "timestamp": "...",
      "url": "...",
      "likes": 0,
      "retweets": 0,
      "replies": 0
    }
  ]
}
```

The scraper reads the user's Posts tab, keeps original posts/quote tweets/self-replies, filters retweets by URL ownership, and targets 100 tweets per scrape.

The scraper only writes `data/users/{handle}.json` and updates `data/state.json` when it collects more than 50 tweets. If it collects 50 or fewer tweets, it prints the handle for manual review and leaves existing data/state untouched.
