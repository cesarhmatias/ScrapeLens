#!/usr/bin/env python3
"""A real Chrome (test binary, temp profile) through the real Relay; optional stranger flood."""
import http.server, json, os, shutil, socketserver, subprocess, sys, tempfile, threading, time, re
exe, chrome, flooder, floodthreads, holdms = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
N = int(os.environ.get("IMGS", "120"))
HOSTS = int(os.environ.get("HOSTS", "24"))
relay_uid = os.environ.get("RELAY_UID"); str_uid = os.environ.get("STRANGER_UID")
def uidkw(u): return {"user": int(u), "group": int(u), "extra_groups": []} if u else {}
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            imgs = "".join(f'<img src="http://h{i%HOSTS}.review.test/i{i}.gif" onload="ok++" onerror="err++">' for i in range(N))
            imgs += '<img src="http://slow.review.test/slow.gif" onload="ok++" onerror="err++">'
            body = f'<html><head><title>x</title><script>var ok=0,err=0;</script></head><body>{imgs}<script>window.onload=function(){{document.body.setAttribute("data-res","ok="+ok+" err="+err)}}</script></body></html>'.encode()
            ctype = "text/html"
        else:
            if "slow" in self.path: time.sleep(float(os.environ.get("SLOW", "3")))
            body = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")
            ctype = "image/gif"
        self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body); self.close_connection = True
class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 2048
web = TS(("127.0.0.1", 0), H); threading.Thread(target=web.serve_forever, daemon=True).start()
os.environ["UPSTREAM_FORWARD"] = f"127.0.0.1:{web.server_address[1]}"
upproc = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=dict(os.environ, UPSTREAM_ONLY="1"))
os.environ["UPSTREAM_PORT"] = upproc.stdout.readline().split()[1]
def lim():
    import resource
    if os.environ.get("RELAY_NOFILE"):
        n = int(os.environ["RELAY_NOFILE"]); resource.setrlimit(resource.RLIMIT_NOFILE, (n, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
sv = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, preexec_fn=lim, **uidkw(relay_uid))
port = int(sv.stdout.readline().split()[1])
def cmd(l): sv.stdin.write(l + "\n"); sv.stdin.flush(); return sv.stdout.readline().strip()
prof = tempfile.mkdtemp(prefix="chrome-review-", dir=os.environ.get("SCEN_TMP"))
if relay_uid: os.chown(prof, int(relay_uid), int(relay_uid))
fl = None
if floodthreads:
    fl = subprocess.Popen([flooder, str(port), os.environ.get("FLOOD_SECS", "40"), str(floodthreads), holdms], stdout=subprocess.PIPE, text=True, **uidkw(str_uid))
    print(f"flood rate target={os.environ.get('RATE','unpaced')}", flush=True)
    time.sleep(1)
args = [chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", f"--user-data-dir={prof}", f"--proxy-server=socks5://127.0.0.1:{port}", "--disable-extensions", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--use-mock-keychain", "--password-store=basic", "--dump-dom", "--timeout=30000", "http://page.review.test/"]
if os.environ.get("NOSANDBOX"): args.insert(1, "--no-sandbox")
env = dict(os.environ); env["HOME"] = prof
t0 = time.time()
c = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, **uidkw(relay_uid))
print("owner", cmd(f"owner {c.pid}"), "chrome pid", c.pid, flush=True)
tree_note = []
def inspect():
    time.sleep(float(os.environ.get("INSPECT_AT", "1.5")))
    if sys.platform != "linux": return
    code = r'''
import os,sys
owner=int(sys.argv[1]); seen=[]; st=[owner]
while st:
    p=st.pop(); seen.append(p)
    try:
        for t in os.listdir(f"/proc/{p}/task"):
            st.extend(int(x) for x in open(f"/proc/{p}/task/{t}/children").read().split())
    except Exception as e: print(p,"children",repr(e))
for p in seen:
    try:
        n=len(os.listdir(f"/proc/{p}/fd")); r="fd-ok %d"%n
    except Exception as e: r=repr(e)
    try:
        ty=[a for a in open(f"/proc/{p}/cmdline").read().split("\0") if a.startswith("--type")]
    except Exception as e: ty=[repr(e)]
    print(p,ty,r)
'''
    o = subprocess.run([sys.executable, "-I", "-c", code, str(c.pid)], capture_output=True, text=True, **uidkw(relay_uid))
    tree_note.append(o.stdout + o.stderr)
peak = [0, 0, 0]
def samp():
    while c.poll() is None:
        try:
            if sys.platform == "linux":
                peak[0] = max(peak[0], len(os.listdir(f"/proc/{sv.pid}/task")))
                peak[2] = max(peak[2], len(os.listdir(f"/proc/{sv.pid}/fd")))
                for l in open(f"/proc/{sv.pid}/status"):
                    if l.startswith("VmRSS"): peak[1] = max(peak[1], int(l.split()[1]))
        except Exception: pass
        time.sleep(0.2)
threading.Thread(target=samp, daemon=True).start()
th = threading.Thread(target=inspect); th.start()
try:
    out_, err_ = c.communicate(timeout=float(os.environ.get("CHROME_TIMEOUT", "90")))
except subprocess.TimeoutExpired:
    c.kill(); out_, err_ = c.communicate(); print("CHROME TIMEOUT", flush=True)
th.join()
m = re.search(r'data-res="([^"]*)"', out_)
print(f"[realchrome floodthreads={floodthreads} hold={holdms} imgs={N+1} hosts={HOSTS} nofile={os.environ.get('RELAY_NOFILE')}] exit={c.returncode} secs={time.time()-t0:.1f} page={m.group(1) if m else None} dom_bytes={len(out_)}", flush=True)
print(f"  relay peak threads={peak[0]} rss_kb={peak[1]} fds={peak[2]}", flush=True)
print("  relay_failures=", cmd("failures"), flush=True)
upproc.stdin.write("x\n"); upproc.stdin.flush(); print("  upstream_connects=", upproc.stdout.readline().count("CONNECT"), flush=True); upproc.kill()
if fl:
    fl.terminate(); fl.wait()
if not m: print("  stderr tail:", err_[-600:], flush=True)
try:
    sv.stdin.write("quit\n"); sv.stdin.flush(); sv.wait(timeout=10)
except Exception: sv.kill()
shutil.rmtree(prof, ignore_errors=True)
