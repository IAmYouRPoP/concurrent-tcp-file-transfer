#!/usr/bin/env python3
"""Black-box tests: talks to the real server over TCP using the project's packet format with TLS.
Usage:  python3 tests/test_server.py build        (or build_asan, see README)"""
import hashlib, os, re, shutil, socket, sqlite3, struct, subprocess, sys, time, uuid, signal, ssl

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(ROOT, "build")
WORK = os.path.join(BUILD, "testrun")
CERTS = os.path.join(ROOT, "certs")
CA_FILE = os.path.join(CERTS, "ca.crt")

# Ensure certificates exist
if not os.path.exists(os.path.join(CERTS, "server.crt")) or not os.path.exists(os.path.join(CERTS, "ca.crt")):
    gen_script = os.path.join(ROOT, "scripts", "generate_certs.py")
    if os.path.exists(gen_script):
        subprocess.run([sys.executable, gen_script, CERTS], check=True)

# --- packet numbers come straight from protocol.hpp, so they can never get out of date ---
src = open(os.path.join(ROOT, "src/common/protocol.hpp")).read()
body = src[src.index("enum class PacketType"):src.index("};")]
body = re.sub(r"//[^\n]*", "", body)   # ignore comments
names = re.findall(r"\b(R(?:EQ|ESP)_[A-Z_]+)", body)
T = {n: i for i, n in enumerate(names)}
R = {i: n for n, i in T.items()}

def pkt(cmd, payload=b"", size=None):
    size = 4 + len(payload) if size is None else size
    return struct.pack("<BBH", 0, T[cmd] if isinstance(cmd, str) else cmd, size) + payload

def fixed(text, n):
    b = text.encode()
    assert len(b) < n
    return b + b"\0" * (n - len(b))

class Conn:
    def __init__(self):
        raw = socket.create_connection(("127.0.0.1", 1312), timeout=5)
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
        ctx.check_hostname = True
        self.s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    def send(self, data): self.s.sendall(data)
    def recv_exact(self, n):
        out = b""
        while len(out) < n:
            try:
                c = self.s.recv(n - len(out))
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                c = b""
            if not c: raise EOFError("server closed the connection")
            out += c
        return out
    def read(self):
        head = self.recv_exact(4)
        size = struct.unpack("<H", head[2:])[0]
        return R.get(head[1], head[1]), head + self.recv_exact(size - 4)
    def rpc(self, cmd, payload=b"", size=None):
        self.send(pkt(cmd, payload, size)); return self.read()
    def close(self):
        try: self.s.close()
        except Exception: pass

def login(c, u, p):
    return c.rpc("REQ_LOGIN", fixed(u, 64) + fixed(p, 64))[0]

def upload(c, name, data, claimed_hash=None):
    h = claimed_hash if claimed_hash is not None else hashlib.md5(data).digest()
    r, _ = c.rpc("REQ_FILE_TRANSFER_START", h + fixed(name, 256))
    if r != "RESP_CONTINUE": return r
    chunks = [data[i:i + 65531] for i in range(0, len(data), 65531)]
    if not chunks: return c.rpc("REQ_FILE_TRANSFER_END")[0]
    for part in chunks[:-1]:
        r, _ = c.rpc("REQ_FILE_TRANSFER_CHUNK", part)
        if r != "RESP_CONTINUE": return r
    return c.rpc("REQ_FILE_TRANSFER_END", chunks[-1])[0]

def download(c, name):
    r, p = c.rpc("REQ_FILE_OPEN", fixed(name, 255))
    if r != "RESP_FILE_OPENED": return r, None, None
    chunks = struct.unpack("<Q", p[8:16])[0]; h = p[16:32]
    data = b""
    for i in range(chunks):
        r, p = c.rpc("REQ_FILE_DOWNLOAD_CHUNK", struct.pack("<IQ", 0, i)[4:] if False else b"\0\0\0\0" + struct.pack("<Q", i))
        assert r == "RESP_FILE_CHUNK", r
        data += p[4:]
    assert c.rpc("REQ_FILE_CLOSE")[0] == "RESP_OK"
    return "OK", data, h

passed = failed = 0
def check(label, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print(f"  PASS  {label}")
    else: failed += 1; print(f"  FAIL  {label} {extra}")

# ---------- set up a clean server ----------
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK)
if os.path.exists(CERTS):
    shutil.copytree(CERTS, os.path.join(WORK, "certs"), dirs_exist_ok=True)
db = sqlite3.connect(os.path.join(WORK, "pcd.db"))
db.execute("CREATE TABLE USERS(UUID TEXT PRIMARY KEY,USERNAME TEXT NOT NULL,PASSWORD TEXT NOT NULL,ROLE INT NOT NULL DEFAULT 0)")
ids = {}
for u, p, role in (("alice", "pass123", 0), ("bob", "secret", 0), ("root", "adminpw", 1), ("root2", "adminpw2", 1)):
    ids[u] = str(uuid.uuid4())
    db.execute("INSERT INTO USERS VALUES(?,?,?,?)", (ids[u], u, hashlib.sha512(p.encode()).hexdigest(), role))
db.commit(); db.close()
logf = open(os.path.join(WORK, "server.log"), "w")
shutil.copyfile(os.path.join(HERE, "lsan.supp"), os.path.join(WORK, "lsan.supp"))
env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=0", UBSAN_OPTIONS="print_stacktrace=1",
           LSAN_OPTIONS="suppressions=lsan.supp")
# Terminate any leftover server from a previous crashed run
try:
    subprocess.run(["pkill", "-9", "-f", os.path.join(BUILD, "server")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
except Exception:
    pass

server_bin = os.path.join(BUILD, "server")
server_crt = os.path.join(WORK, "certs", "server.crt")
server_key = os.path.join(WORK, "certs", "server.key")
cmd = [server_bin, "--cert", server_crt, "--key", server_key]
server = subprocess.Popen(cmd, cwd=WORK, stdout=logf, stderr=subprocess.STDOUT, env=env)

time.sleep(1.0)
if server.poll() is not None:
    logf.flush()
    log = open(os.path.join(WORK, "server.log")).read()
    print(f"FATAL: Server exited unexpectedly with code {server.returncode}!\n--- server.log ---\n{log}\n------------------")
    sys.exit(1)
tmp = os.path.join(WORK, "tmp")

print("== login and basic commands")
a = Conn(); b = Conn()
check("command before login is refused", a.rpc("REQ_FILE_LIST")[0] == "RESP_NOT_LOGGED_IN")
check("wrong password refused", login(a, "alice", "nope") == "RESP_BAD_LOGIN")
check("alice logs in", login(a, "alice", "pass123") == "RESP_LOGGED_IN")
check("bob logs in", login(b, "bob", "secret") == "RESP_LOGGED_IN")
check("ping works", a.rpc("REQ_PING")[0] == "RESP_PONG")
check("mkdir ok", a.rpc("REQ_MKDIR", fixed("docs", 512))[0] == "RESP_OK")
check("bob has a private folder", b.rpc("REQ_MKDIR", fixed("bobs_private", 512))[0] == "RESP_OK")

print("== path safety")
for bad in ("..", ".", "../x", "a/b", ""):
    check(f"rm {bad!r} refused", a.rpc("REQ_REMOVE_PATH", fixed(bad, 512))[0] == "RESP_IO_ERROR")
check("mkdir '..' refused", a.rpc("REQ_MKDIR", fixed("..", 512))[0] == "RESP_IO_ERROR")
check("bob's folder still exists after attacks", os.path.isdir(os.path.join(tmp, ids["bob"], "bobs_private")))
check("alice's folder still exists after attacks", os.path.isdir(os.path.join(tmp, ids["alice"], "docs")))
a.rpc("REQ_CHANGE_WORKING_DIRECTORY", fixed("../../..", 512))
_, p = a.rpc("REQ_CURRENT_DIRECTORY")
check("cd ../../.. cannot leave the user folder", p[4:].split(b"\0")[0].decode() == f"./tmp/{ids['alice']}", p[4:30])
check("cd /etc does not reach the real /etc", a.rpc("REQ_CHANGE_WORKING_DIRECTORY", fixed("/etc", 512))[0] == "RESP_IO_ERROR")
check("mv outside user folder refused", a.rpc("REQ_MOVE_FILE", fixed("docs", 512) + fixed("../" + ids["bob"] + "/stolen", 512))[0] == "RESP_IO_ERROR")
check("cp from another user refused", a.rpc("REQ_COPY_FILE", fixed("../" + ids["bob"] + "/bobs_private", 512) + fixed("mine", 512))[0] == "RESP_IO_ERROR")
check("mv with absolute path refused", a.rpc("REQ_MOVE_FILE", fixed("/etc/hostname", 512) + fixed("x", 512))[0] == "RESP_IO_ERROR")
sibling = ids["alice"] + "x"
os.makedirs(os.path.join(tmp, sibling), exist_ok=True)
check("sibling folder with same start refused (prefix trick)", a.rpc("REQ_MOVE_FILE", fixed("docs", 512) + fixed("../" + sibling + "/docs", 512))[0] == "RESP_IO_ERROR")
check("compress with ../ in archive name refused", a.rpc("REQ_COMPRESS", bytes([0, 2, 0, 1]) + b"\0" * (128 * 256) + fixed("../evil", 256))[0] == "RESP_IO_ERROR")
check("compress with too many files refused", a.rpc("REQ_COMPRESS", bytes([0, 2, 0, 200]) + b"\0" * (128 * 256) + fixed("a", 256))[0] == "RESP_IO_ERROR")
check("mv inside own folder works", a.rpc("REQ_MOVE_FILE", fixed("docs", 512) + fixed("docs2", 512))[0] == "RESP_OK")
check("cp onto existing target does not crash the server", a.rpc("REQ_COPY_FILE", fixed("docs2", 512) + fixed("docs2", 512))[0] == "RESP_IO_ERROR")
check("server still alive", a.rpc("REQ_PING")[0] == "RESP_PONG")

print("== checksum: upload and download")
data = os.urandom(200000)
check("upload with right checksum ok", upload(a, "big.bin", data) == "RESP_FILE_TRANSFER_OK")
check("stored file is identical", open(os.path.join(tmp, ids["alice"], "big.bin"), "rb").read() == data)
r, got, h = download(a, "big.bin")
check("download returns identical bytes", got == data)
check("download announces the right checksum", h == hashlib.md5(data).digest())
check("upload with WRONG checksum is rejected", upload(a, "bad.bin", data, claimed_hash=b"\x01" * 16) == "RESP_CRC_FAILED")
check("damaged file was deleted", not os.path.exists(os.path.join(tmp, ids["alice"], "bad.bin")))
check("empty file upload works", upload(a, "empty.txt", b"") == "RESP_FILE_TRANSFER_OK")
check("exactly one full chunk works", upload(a, "one.bin", os.urandom(65531)) == "RESP_FILE_TRANSFER_OK")
upload(a, "over.txt", b"X" * 5000)
upload(a, "over.txt", b"short")
check("uploading a smaller file over a bigger one leaves no old tail", open(os.path.join(tmp, ids["alice"], "over.txt"), "rb").read() == b"short")
check("upload name with '/' refused", upload(a, "docs2/x", b"1") == "RESP_IO_ERROR")
check("upload name '..' refused", upload(a, "..", b"1") == "RESP_IO_ERROR")
check("chunk without a start is refused (no write to fd 0)", a.rpc("REQ_FILE_TRANSFER_CHUNK", b"abc")[0] == "RESP_IO_ERROR")
check("download of a folder refused", download(a, "docs2")[0] == "RESP_IO_ERROR")
check("download of a missing file refused", download(a, "nope.txt")[0] == "RESP_IO_ERROR")
check("download chunk without open file gives one error reply", a.rpc("REQ_FILE_DOWNLOAD_CHUNK", b"\0\0\0\0" + struct.pack("<Q", 0))[0] == "RESP_IO_ERROR")
check("ping still answers right after (no extra reply left over)", a.rpc("REQ_PING")[0] == "RESP_PONG")

print("== unfinished upload is cleaned up when the client disconnects")
c = Conn(); login(c, "alice", "pass123")
c.rpc("REQ_FILE_TRANSFER_START", hashlib.md5(b"x").digest() + fixed("half.bin", 256))
c.rpc("REQ_FILE_TRANSFER_CHUNK", b"partial data")
check("partial file exists during the upload", os.path.exists(os.path.join(tmp, ids["alice"], "half.bin")))
c.close(); time.sleep(0.6)
check("partial file removed after disconnect", not os.path.exists(os.path.join(tmp, ids["alice"], "half.bin")))

print("== malformed packets must not crash the server")
m = Conn()
m.send(struct.pack("<BBH", 0, T["REQ_PING"], 2))          # size smaller than the header
time.sleep(0.4)
try:
    m.s.settimeout(1)
    res = m.s.recv(10)
    closed = (res == b"")
except (ssl.SSLZeroReturnError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError, socket.timeout):
    closed = True
except Exception:
    closed = False
check("packet with size 2 -> connection dropped", closed)
m = Conn(); m.send(struct.pack("<BBH", 0, T["RESP_OK"], 4)); r = m.read()[0]
check("response type sent as a request -> error reply, no crash", r == "RESP_IO_ERROR")
m = Conn(); m.send(struct.pack("<BBH", 0, 250, 4)); r = m.read()[0]
check("unknown command number 250 -> error reply, no crash", r == "RESP_IO_ERROR")
m = Conn(); m.send(pkt("REQ_LOGIN", b"A" * 128))          # no terminating zero in username/password
check("unterminated username/password -> bad login, no crash", m.read()[0] == "RESP_BAD_LOGIN")
check("server still alive after all that", a.rpc("REQ_PING")[0] == "RESP_PONG")
# a client that disconnects while a big reply is on its way (used to raise SIGPIPE and kill the server)
d = Conn(); login(d, "alice", "pass123")
for _ in range(20): d.send(pkt("REQ_FILE_LIST"))
d.s.close(); time.sleep(0.5)
check("server survives a client leaving mid-reply", a.rpc("REQ_PING")[0] == "RESP_PONG")

print("== logout and admin")
check("normal user gets 'requires admin'", a.rpc("REQ_SERVER_STATUS")[0] == "RESP_REQUIRES_ADMIN")
ad = Conn(); ad2 = Conn()
check("admin logs in", login(ad, "root", "adminpw") == "RESP_LOGGED_IN")
t0 = time.time(); r, p = ad.rpc("REQ_SERVER_STATUS")
cpu = struct.unpack("<b", p[4 + 16:4 + 17])[0] if len(p) > 20 else None
check("status works", r == "RESP_SERVER_STATUS_RESPONSE")
check("second admin refused while one is online", login(ad2, "root2", "adminpw2") == "RESP_ADMIN_ALREADY_CONNECTED")
check("logout ok", ad.rpc("REQ_LOGOUT")[0] == "RESP_OK")
check("after logout the admin commands are refused", ad.rpc("REQ_SERVER_STATUS")[0] == "RESP_NOT_LOGGED_IN")
check("logged-out admin logging in as a normal user is NOT admin", login(ad, "alice", "pass123") == "RESP_LOGGED_IN" and ad.rpc("REQ_SERVER_STATUS")[0] == "RESP_REQUIRES_ADMIN")
check("second admin can log in after the first left", login(ad2, "root2", "adminpw2") == "RESP_LOGGED_IN")
ad2.close(); time.sleep(0.5)
ad3 = Conn(); check("admin slot is freed when an admin disconnects", login(ad3, "root", "adminpw") == "RESP_LOGGED_IN")
check("admin clean works", ad3.rpc("REQ_CLEAN")[0] == "RESP_OK")
check("clean removed the user folders", not os.path.exists(os.path.join(tmp, ids["bob"])))

# ---------- shut down and read the sanitizer report ----------
for x in (a, b, ad, ad3):
    try: x.close()
    except Exception: pass
time.sleep(0.3)
alive = server.poll() is None
check("server process never crashed", alive)
if alive: server.send_signal(signal.SIGINT)
try: server.wait(timeout=10)
except Exception: server.kill()
logf.close()
log = open(os.path.join(WORK, "server.log")).read()
bad = [l for l in log.splitlines() if re.search(r"ERROR: (Address|Leak)Sanitizer|runtime error|SUMMARY:", l)]
check("no AddressSanitizer / LeakSanitizer / UBSan reports in the server log", not bad, "\n".join(bad[:8]))
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
