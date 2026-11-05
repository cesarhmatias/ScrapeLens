import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
print("meta version:", c.execute("select value from meta where key='version'").fetchall())
for name, enc in c.execute("select name, encrypted_value from cookies"):
    print("cookie", name, "prefix:", enc[:3])
