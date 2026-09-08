"""End-to-end MCP wire test over stdio.

The predecessor passed a happy-path wire test (initialize -> 17 tools ->
one successful call) and still died on the first bad argument. This exercises
the failure paths deliberately and, after each one, checks the server is
still answering.
"""
from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Client:
    def __init__(self) -> None:
        self.p = subprocess.Popen(
            [sys.executable, str(ROOT / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT),
        )
        self.q: queue.Queue = queue.Queue()
        self.err: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, args=(self.p.stdout, self.q), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.p.stderr, self.err), daemon=True).start()
        self._id = 0

    @staticmethod
    def _pump(stream, q) -> None:
        for line in stream:
            q.put(line)
        q.put(None)

    def send(self, obj: dict) -> None:
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def recv(self, timeout: float = 60.0):
        try:
            line = self.q.get(timeout=timeout)
        except queue.Empty:
            return "<TIMEOUT>"
        if line is None:
            return "<STDOUT CLOSED>"
        return json.loads(line)

    def handshake(self) -> dict:
        self._id += 1
        self.send({
            "jsonrpc": "2.0", "id": self._id, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "wire-test", "version": "1"}},
        })
        r = self.recv()
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        return r

    def list_tools(self) -> list[str]:
        self._id += 1
        self.send({"jsonrpc": "2.0", "id": self._id, "method": "tools/list", "params": {}})
        r = self.recv()
        return [t["name"] for t in r["result"]["tools"]]

    def call(self, name: str, args: dict, timeout: float = 120.0):
        self._id += 1
        self.send({
            "jsonrpc": "2.0", "id": self._id, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })
        r = self.recv(timeout)
        if not isinstance(r, dict):
            return r
        try:
            return json.loads(r["result"]["content"][0]["text"])
        except (KeyError, IndexError, json.JSONDecodeError):
            return r

    def stderr_tail(self, n: int = 500) -> str:
        time.sleep(0.3)
        out = []
        while not self.err.empty():
            v = self.err.get()
            if v:
                out.append(v)
        return "".join(out)[-n:]

    def kill(self) -> None:
        self.p.kill()


def main() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool, detail: str = "") -> None:
        status = "PASS" if cond else "FAIL"
        print(f"  [{status}] {label}" + (f" -- {detail}" if detail and not cond else ""))
        if not cond:
            failures.append(label)

    c = Client()
    try:
        hs = c.handshake()
        check("initialize", isinstance(hs, dict) and "result" in hs)
        names = c.list_tools()
        print(f"\n  {len(names)} tools: {', '.join(names)}\n")
        check("tool list non-empty", len(names) >= 12)

        # ---- happy path -------------------------------------------------
        r = c.call("re_identify", {"binary": r"C:\Windows\System32\notepad.exe"})
        check("re_identify on a real PE", r.get("ok") is True)
        check("identity is content-addressed", bool(r.get("target", {}).get("sha256")))
        check("architecture reported", r["target"]["bits"] == 64)
        check("decoder selected for 64-bit", r["result"]["decoder"] == "x86-64")

        # ---- the input that killed the predecessor -----------------------
        print("\n  --- failure paths (each must return an error AND leave the server alive) ---")
        cases = [
            ("non-binary text file", "re_identify", {"binary": str(ROOT / "README.md")}),
            ("directory as target", "re_identify", {"binary": str(ROOT)}),
            ("missing file", "re_identify", {"binary": str(ROOT / "nope.bin")}),
            ("unmapped address", "re_disasm", {"binary": r"C:\Windows\System32\notepad.exe",
                                               "address": "0xdead0000"}),
            ("garbage address string", "re_disasm", {"binary": r"C:\Windows\System32\notepad.exe",
                                                     "address": "not-an-address"}),
            ("bad regex", "re_strings", {"binary": r"C:\Windows\System32\notepad.exe",
                                         "pattern": "([unclosed", "limit": 5}),
            ("missing fingerprint db", "re_match_builds", {"db_a": "no_such_a.json",
                                                           "db_b": "no_such_b.json"}),
        ]
        for label, tool_name, args in cases:
            resp = c.call(tool_name, args)
            alive = isinstance(resp, dict)
            structured = alive and ("error" in resp or resp.get("ok") is not None)
            check(f"{label}: structured response", structured, repr(resp)[:120])
            probe = c.call("re_sniff", {"path": str(ROOT / "server.py")})
            check(f"{label}: server still alive", isinstance(probe, dict) and probe.get("ok") is True,
                  repr(probe)[:120])

        # ---- in-band warnings -------------------------------------------
        print("\n  --- evidence and warnings ---")
        r = c.call("re_disasm", {"binary": r"C:\Windows\System32\notepad.exe",
                                 "address": "0x140030000", "count": 4})
        if r.get("ok"):
            codes = {w["code"] for w in r.get("warnings", [])}
            check("non-executable decode is flagged in band",
                  "non_executable_section" in codes or r.get("reliability") != "sound",
                  str(codes))

        r = c.call("re_translate", {"binary": r"C:\Windows\System32\notepad.exe", "address": "0x1000"})
        check("re_translate returns all three spaces",
              r.get("ok") and set(r["result"]["interpretations"]) >= {"as_va", "as_rva", "as_file_offset"})

        # ---- caching -----------------------------------------------------
        print("\n  --- caching ---")
        t0 = time.time()
        r1 = c.call("re_callgraph", {"binary": r"C:\Windows\System32\notepad.exe"})
        t1 = time.time()
        r2 = c.call("re_callgraph", {"binary": r"C:\Windows\System32\notepad.exe"})
        t2 = time.time()
        check("callgraph succeeds", r1.get("ok") is True)
        cached = r2.get("code_index", {}).get("cached")
        check("second call served from cache", cached is True, str(r2.get("code_index")))
        print(f"       cold {t1-t0:.2f}s -> warm {t2-t1:.2f}s")

        # ---- policy ------------------------------------------------------
        print("\n  --- policy surface ---")
        r = c.call("re_kb_policy", {})
        ok = r.get("ok") and "classes" in r.get("result", {})
        check("policy is introspectable", bool(ok))
        if ok:
            cls = r["result"]["classes"]
            verifiable = [k for k, v in cls.items() if v["verifiable"]]
            check("some classes are machine-verifiable", len(verifiable) >= 5, str(verifiable))

        err = c.stderr_tail()
        if err.strip():
            print(f"\n  server stderr tail:\n    {err.strip()[:300]}")
    finally:
        c.kill()

    print("\n" + ("ALL WIRE CHECKS PASSED" if not failures else f"FAILURES: {failures}"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
