from db import Database

db = Database()

users = db.get_users()
states = db.get_all_scrape_states()
total_users = len(users)

scraped = 0
pending_scrape = 0
taxonomy_done = 0
taxonomy_pending = 0
total_tweets = 0
latest = ""

for h in users:
    s = states.get(h)
    if s:
        scraped += 1
        total_tweets += s["tweet_count"]
        if s["taxonomy_updated"]:
            taxonomy_done += 1
        else:
            taxonomy_pending += 1
        if s["scraped_at"] > latest:
            latest = s["scraped_at"]
    else:
        pending_scrape += 1

print(f"Users:   {total_users}")
print(f"Scraped: {scraped}  ({total_tweets} tweets total)")
print(f"Pending: {pending_scrape}  (never scraped)")
print(f"")
print(f"Taxonomy done:    {taxonomy_done}")
print(f"Taxonomy pending: {taxonomy_pending}")
if latest:
    print(f"")
    print(f"Latest scrape: {latest}")
print(f"")

thin = []
for h in users:
    t = db.get_taxonomy(h)
    if t:
        c = t.get("scrape_data_tweet_count", 0)
        if c and c < 100:
            thin.append((h, c))
    s = states.get(h)
    if s and s["tweet_count"] < 51 and s["tweet_count"] > 0:
        thin.append((h, s["tweet_count"]))

if thin:
    print("Thin/low-confidence users:")
    for h, c in sorted(set(thin)):
        print(f"  @{h}: {c}t")
