import asyncio
import re
from app.config import get_settings
from app.grafana_client import GrafanaClient

async def strip_prefixes():
    settings = get_settings()
    client = GrafanaClient(settings)
    rules = await client.list_alert_rules()
    print(f"Total rules found: {len(rules)}")
    for r in rules:
        title = r.get("title", "")
        # Remove [Global], [Banco Alfa], [QualquerCoisa]
        new_title = re.sub(r"^\[.*?\]\s*", "", title).strip()
        if new_title != title:
            print(f"Updating '{title}' -> '{new_title}' (UID: {r.get('uid')})")
            r["title"] = new_title
            await client.update_alert_rule(r["uid"], r)
        else:
            print(f"Kept unchanged: '{title}'")
    print("Done!")

if __name__ == "__main__":
    asyncio.run(strip_prefixes())

