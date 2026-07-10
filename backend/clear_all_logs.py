import sqlite3

conn = sqlite3.connect("sentinelgrid.db")
c = conn.cursor()

# List all tables
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in c.fetchall()]
print("All tables:", tables)

# Tables to clear (data/logs only, not config/users/orgs/assets)
clear_tables = [
    "security_telemetry",
    "incidents",
    "response_actions",
    "security_events",
    "audit_logs",
    "notification_configs",
]

for t in clear_tables:
    if t in tables:
        c.execute(f"DELETE FROM {t}")
        print(f"  Cleared: {t}")
    else:
        print(f"  Skipped (not found): {t}")

conn.commit()
conn.close()
print("\nAll logs and incident data cleared!")
