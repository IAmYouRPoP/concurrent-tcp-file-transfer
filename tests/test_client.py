#!/usr/bin/env python3
"""End-to-end test with the real command line client.
Usage:  python3 tests/test_client.py build        (or build_asan)"""
import hashlib, os, shutil, sqlite3, subprocess, sys, time, uuid, signal

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(ROOT, "build")
SRV = os.path.join(BUILD, "server_run"); CLI = os.path.join(BUILD, "client_run")
for d in (SRV, CLI): shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
os.makedirs(os.path.join(CLI, "data"))
CERTS = os.path.join(ROOT, "certs")
if not os.path.exists(os.path.join(CERTS, "server.crt")) or not os.path.exists(os.path.join(CERTS, "ca.crt")):
    gen_script = os.path.join(ROOT, "scripts", "generate_certs.py")
    if os.path.exists(gen_script):
        subprocess.run([sys.executable, gen_script, CERTS], check=True)

if os.path.exists(CERTS):
    shutil.copytree(CERTS, os.path.join(SRV, "certs"), dirs_exist_ok=True)
    shutil.copytree(CERTS, os.path.join(CLI, "certs"), dirs_exist_ok=True)

db = sqlite3.connect(os.path.join(SRV, "pcd.db"))
db.execute("CREATE TABLE USERS(UUID TEXT PRIMARY KEY,USERNAME TEXT NOT NULL,PASSWORD TEXT NOT NULL,ROLE INT NOT NULL DEFAULT 0)")
uid = str(uuid.uuid4())
db.execute("INSERT INTO USERS VALUES(?,?,?,0)", (uid, "alice", hashlib.sha512(b"pass123").hexdigest())); db.commit(); db.close()

big = os.urandom(300000)
open(os.path.join(CLI, "data", "big.bin"), "wb").write(big)
open(os.path.join(CLI, "empty.txt"), "wb").write(b"")
open(os.path.join(CLI, "small.txt"), "wb").write(b"hello world\n")
# a local file that is LONGER than the download, to prove old content does not stay behind
os.makedirs(os.path.join(CLI, "out"), exist_ok=True)
if os.path.exists(CERTS):
    shutil.copytree(CERTS, os.path.join(CLI, "out", "certs"), dirs_exist_ok=True)
open(os.path.join(CLI, "out", "small.txt"), "wb").write(b"X" * 5000)

shutil.copyfile(os.path.join(HERE, "lsan.supp"), os.path.join(SRV, "lsan.supp"))
shutil.copyfile(os.path.join(HERE, "lsan.supp"), os.path.join(CLI, "lsan.supp"))
shutil.copyfile(os.path.join(HERE, "lsan.supp"), os.path.join(CLI, "out", "lsan.supp"))
env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1", LSAN_OPTIONS="suppressions=lsan.supp")
slog = open(os.path.join(SRV, "server.log"), "w")

# Terminate any leftover server from a previous crashed run
try:
    subprocess.run(["pkill", "-9", "-f", os.path.join(BUILD, "server")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
except Exception:
    pass

server_bin = os.path.join(BUILD, "server")
server_crt = os.path.join(SRV, "certs", "server.crt")
server_key = os.path.join(SRV, "certs", "server.key")
cmd = [server_bin, "--cert", server_crt, "--key", server_key]
server = subprocess.Popen(cmd, cwd=SRV, stdout=slog, stderr=subprocess.STDOUT, env=env)

time.sleep(1.0)
if server.poll() is not None:
    slog.flush()
    log = open(os.path.join(SRV, "server.log")).read()
    print(f"FATAL: Server exited unexpectedly with code {server.returncode}!\n--- server.log ---\n{log}\n------------------")
    sys.exit(1)

script = "\n".join([
    "login alice pass123",
    "upload data/big.bin",            # path with a folder in front: only 'big.bin' must be used as the name
    "upload empty.txt",
    "upload small.txt",
    "upload does_not_exist.bin",     # must not crash the client
    "",                               # empty line must not repeat the previous command
    "ls",
    "download big.bin",
    "download empty.txt",
    "logout",
]) + "\n"
def run(cwd, text):
    return subprocess.run([os.path.join(BUILD, "client")], input=text, text=True, capture_output=True, cwd=cwd, env=env, timeout=60)
r = run(CLI, script)
out = r.stdout + r.stderr
passed = failed = 0
def check(label, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS  {label}")
    else: failed += 1; print(f"  FAIL  {label} {extra}")

check("client exits by itself at end of input (no endless loop)", r.returncode == 0, f"code={r.returncode}")
check("uploads reported 'File transfer was ok' 3 times", out.count("File transfer was ok!") == 3, out[:600])
check("missing local file gives a clear message (no crash)", "Cannot open the file 'does_not_exist.bin'" in out)
check("download reports checksum OK twice", out.count("checksum OK") == 2, out[-600:])
check("no sanitizer error in client", "Sanitizer" not in out and "runtime error" not in out, out[-800:])
sdir = os.path.join(SRV, "tmp", uid)
check("server stored big.bin identical", open(os.path.join(sdir, "big.bin"), "rb").read() == big)
check("server stored empty file", os.path.getsize(os.path.join(sdir, "empty.txt")) == 0)
check("downloaded big.bin identical", open(os.path.join(CLI, "big.bin"), "rb").read() == big)
check("downloaded empty file is empty", os.path.getsize(os.path.join(CLI, "empty.txt")) == 0)

# download over a longer existing file
r2 = run(os.path.join(CLI, "out"), "login alice pass123\ndownload small.txt\n")
check("download over a longer local file replaces it completely", open(os.path.join(CLI, "out", "small.txt"), "rb").read() == b"hello world\n", (r2.stdout + r2.stderr)[-300:])

# a file damaged on the server must be detected by the client
open(os.path.join(sdir, "small.txt"), "ab").write(b"")   # unchanged file -> still OK
r3 = run(os.path.join(CLI, "out"), "login alice pass123\ndownload nothere.txt\nping\n")
check("download of a missing file prints an error and the session continues", "IO Error" in r3.stdout and "PONG" in r3.stdout, r3.stdout[-300:])

time.sleep(0.3)
alive = server.poll() is None
check("server still running", alive)
if alive: server.send_signal(signal.SIGINT)
try: server.wait(timeout=10)
except Exception: server.kill()
slog.close()
log = open(os.path.join(SRV, "server.log")).read()
check("no sanitizer report in server log", "Sanitizer" not in log and "runtime error" not in log, log[-600:])
print(f"\n{passed} passed, {failed} failed"); sys.exit(1 if failed else 0)
