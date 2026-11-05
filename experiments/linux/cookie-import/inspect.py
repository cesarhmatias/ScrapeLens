# Lists the cookies of a Chromium or Firefox cookie database (read-only).
# Usage: inspect.py <Cookies|cookies.sqlite>
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
tables = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
if "moz_cookies" in tables:
    print("firefox cookies:", c.execute("select count(*) from moz_cookies").fetchone()[0])
    for name, value, host in c.execute("select name, value, host from moz_cookies"):
        print("cookie", name, "value-prefix:", (value or "")[:3], "host:", host)
else:
    print("meta version:", c.execute("select value from meta where key='version'").fetchall())
    for name, enc, value in c.execute("select name, encrypted_value, value from cookies"):
        print("cookie", name, "prefix:", (enc or b"")[:3], "plain-len:", len(value or b""))
