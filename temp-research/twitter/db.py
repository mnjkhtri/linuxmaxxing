import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "twitter.db"

SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _get_version(self) -> int:
        cur = self.conn.execute(
            "CREATE TABLE IF NOT EXISTS _schema (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        cur = self.conn.execute("SELECT COALESCE(MAX(version), 0) FROM _schema")
        return cur.fetchone()[0]

    def _migrate(self):
        version = self._get_version()
        if version < 1:
            self._migrate_v1()

    def _migrate_v1(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                handle TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS scrape_state (
                handle TEXT PRIMARY KEY,
                scraped_at TEXT NOT NULL,
                tweet_count INTEGER NOT NULL,
                taxonomy_updated INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS tweets (
                handle TEXT NOT NULL,
                tweet_id TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                likes INTEGER NOT NULL DEFAULT 0,
                retweets INTEGER NOT NULL DEFAULT 0,
                replies INTEGER NOT NULL DEFAULT 0,
                scraped_at TEXT NOT NULL,
                PRIMARY KEY (handle, tweet_id)
            );
            CREATE TABLE IF NOT EXISTS taxonomy (
                handle TEXT PRIMARY KEY,
                scrape_data_used_from TEXT,
                scrape_data_tweet_count INTEGER,
                data TEXT NOT NULL
            );
        """)
        self.conn.execute(
            "INSERT INTO _schema (version, applied_at) VALUES (?, ?)",
            (1, now_iso()),
        )
        self.conn.commit()

    # ---- Users universe ----

    def get_users(self) -> list[str]:
        rows = self.conn.execute("SELECT handle FROM users ORDER BY handle").fetchall()
        return [r["handle"] for r in rows]

    def add_users(self, handles: list[str]):
        for h in handles:
            self.conn.execute(
                "INSERT OR IGNORE INTO users (handle) VALUES (?)",
                (h.lower(),),
            )
        self.conn.commit()

    # ---- Scrape state ----

    def get_scrape_state(self, handle: str) -> dict | None:
        row = self.conn.execute(
            "SELECT scraped_at, tweet_count, taxonomy_updated FROM scrape_state WHERE handle = ?",
            (handle.lower(),),
        ).fetchone()
        if not row:
            return None
        return {
            "scraped_at": row["scraped_at"],
            "tweet_count": row["tweet_count"],
            "taxonomy_updated": bool(row["taxonomy_updated"]),
        }

    def get_all_scrape_states(self) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT handle, scraped_at, tweet_count, taxonomy_updated FROM scrape_state"
        ).fetchall()
        return {
            r["handle"]: {
                "scraped_at": r["scraped_at"],
                "tweet_count": r["tweet_count"],
                "taxonomy_updated": bool(r["taxonomy_updated"]),
            }
            for r in rows
        }

    def set_taxonomy_updated(self, handle: str, updated: bool):
        self.conn.execute(
            "UPDATE scrape_state SET taxonomy_updated = ? WHERE handle = ?",
            (1 if updated else 0, handle.lower()),
        )
        self.conn.commit()

    def handle_in_state(self, handle: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM scrape_state WHERE handle = ?", (handle.lower(),)
        ).fetchone()
        return row is not None

    # ---- Tweets (latest scrape) ----

    def save_tweets(self, handle: str, scraped_at: str, tweet_count: int, tweets: list[dict]):
        handle = handle.lower()
        self.conn.execute("DELETE FROM tweets WHERE handle = ?", (handle,))
        self.conn.executemany(
            """INSERT INTO tweets (handle, tweet_id, text, timestamp, url, likes, retweets, replies, scraped_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    handle,
                    t["tweet_id"],
                    t["text"],
                    t["timestamp"],
                    t["url"],
                    t.get("likes", 0),
                    t.get("retweets", 0),
                    t.get("replies", 0),
                    scraped_at,
                )
                for t in tweets
            ],
        )
        self.conn.execute(
            """INSERT OR REPLACE INTO scrape_state (handle, scraped_at, tweet_count, taxonomy_updated)
               VALUES (?, ?, ?, 0)""",
            (handle, scraped_at, tweet_count),
        )
        self.conn.commit()

    def get_tweets(self, handle: str) -> list[dict]:
        rows = self.conn.execute(
            """SELECT tweet_id, text, timestamp, url, likes, retweets, replies, scraped_at
               FROM tweets WHERE handle = ? ORDER BY timestamp DESC""",
            (handle.lower(),),
        ).fetchall()
        return [
            {
                "tweet_id": r["tweet_id"],
                "text": r["text"],
                "timestamp": r["timestamp"],
                "url": r["url"],
                "likes": r["likes"],
                "retweets": r["retweets"],
                "replies": r["replies"],
            }
            for r in rows
        ]

    def get_scrape_data(self, handle: str) -> dict | None:
        state = self.get_scrape_state(handle)
        if not state:
            return None
        tweets = self.get_tweets(handle)
        if not tweets and state["tweet_count"] > 0:
            return None
        return {
            "scraped_at": state["scraped_at"],
            "tweet_count": state["tweet_count"],
            "tweets": tweets,
        }

    # ---- Taxonomy ----

    def get_taxonomy(self, handle: str) -> dict | None:
        row = self.conn.execute(
            "SELECT data, scrape_data_used_from, scrape_data_tweet_count FROM taxonomy WHERE handle = ?",
            (handle.lower(),),
        ).fetchone()
        if not row:
            return None
        data = json.loads(row["data"])
        return data

    def save_taxonomy(self, handle: str, taxonomy: dict):
        handle = handle.lower()
        used_from = taxonomy.get("scrape_data_used_from", "")
        tweet_count = taxonomy.get("scrape_data_tweet_count")
        self.conn.execute(
            """INSERT OR REPLACE INTO taxonomy (handle, scrape_data_used_from, scrape_data_tweet_count, data)
               VALUES (?, ?, ?, ?)""",
            (handle, used_from, tweet_count, json.dumps(taxonomy)),
        )
        self.conn.commit()

    def taxonomy_exists(self, handle: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM taxonomy WHERE handle = ?", (handle.lower(),)
        ).fetchone()
        return row is not None

    def close(self):
        self.conn.close()
