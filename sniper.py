#!/usr/bin/env python3
"""Sniper: monitor-only. Giden/gelen TCP baglantilarini duz metin .log dosyalarina yazar, engellemez.

Kurulum yok. Calistirmak icin:  sudo python3 sniper.py
Durdurmak icin: Ctrl+C
Gereken paketler (Debian/Ubuntu): python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

Loglar betigin bulundugu dizinde olusur:
  outbound-dump.log  (giden baglantilar)
  inbound-dump.log   (gelen baglantilar)
"""
import os
import sys
import pwd
import json
import time
import signal
import socket
import logging
import logging.handlers
import argparse
import ipaddress
import ctypes as ct
import subprocess
from datetime import datetime, timezone, timedelta

if os.geteuid() != 0:
    print("Sniper root olarak calistirilmalidir: sudo python3 sniper.py", file=sys.stderr)
    sys.exit(1)

try:
    from bcc import BPF
except Exception as e:
    print(f"BCC import hatasi: {e}\nKurulum: sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)",
          file=sys.stderr)
    sys.exit(1)

parser = argparse.ArgumentParser(description="Sniper: eBPF ile giden/gelen TCP baglanti izleme ve kayit (monitor-only)")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
parser.add_argument("--log-dir", default=SCRIPT_DIR,
                    help="outbound-dump.log ve inbound-dump.log dizini (varsayilan: betigin bulundugu dizin)")
parser.add_argument("--format", choices=("text", "json"), default="text",
                    help="Log bicimi: text = okunabilir satir (varsayilan), json = satir basina bir JSON (JSON Lines)")
parser.add_argument("--no-cmd", action="store_true", help="Log dosyasina komut satirini yazma (parola icerebilir)")
parser.add_argument("--max-mb", type=int, default=50, help="Bir log dosyasinin azami boyutu, MB (asinca donusum yapilir)")
parser.add_argument("--backups", type=int, default=5, help="Saklanacak eski log dosyasi sayisi (.log.1, .log.2, ...)")
parser.add_argument("--log-loopback", action="store_true", help="127.0.0.1 <-> 127.0.0.1 baglantilari da kaydet")
parser.add_argument("--ignore-private", action="store_true", help="Hedefi ozel IP (10.x, 192.168.x, fc00::/7...) olanlari atla")
parser.add_argument("--ignore-root", action="store_true", help="root kullanicisinin baglantilarini atla")
parser.add_argument("--no-host", action="store_true", help="Alan adi tahminini (DNS/SNI) kapat")
parser.add_argument("--quiet", action="store_true", help="Canli ekran ciktisini kapat (yalnizca log dosyasina yaz)")
parser.add_argument("--show-cmd", action="store_true", help="Canli ciktida komut satirini da goster (parola icerebilir)")
parser.add_argument("--no-color", action="store_true", help="Canli ciktida renkleri kapat")
parser.add_argument("--no-banner", action="store_true", help="Acilis bannerini gosterme")
ARGS = parser.parse_args()

LOG_DIR = ARGS.log_dir
IGNORE_LOOPBACK = not ARGS.log_loopback
IGNORE_PRIVATE = ARGS.ignore_private
IGNORE_ROOT = ARGS.ignore_root
ENABLE_HOST_ENRICHMENT = not ARGS.no_host
HOSTNAME = socket.gethostname()

OUT_LOG = os.path.join(LOG_DIR, "outbound-dump.log")
IN_LOG = os.path.join(LOG_DIR, "inbound-dump.log")

# Yeni olusan log dosyalari yalnizca root + grup tarafindan okunabilsin (640)
os.umask(0o027)

HOST_CACHE = {}
HOST_TTL = 20

# ------------------------------------------------------------- log dosyalari
def make_logger(name, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=max(ARGS.max_mb, 1) * 1024 * 1024,
        backupCount=max(ARGS.backups, 0), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger

LOGGERS = {}

def local_time(ts_iso):
    """UTC ISO zaman damgasini yerel saatle 'YYYY-MM-DD HH:MM:SS' yapar."""
    try:
        return datetime.fromisoformat(ts_iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_iso

def format_record(direction, rec):
    if ARGS.format == "json":
        out = dict(rec)
        out["direction"] = direction
        if ARGS.no_cmd:
            out.pop("cmdline", None)
        return json.dumps(out, ensure_ascii=False, separators=(",", ":"))

    local = fmt_addr(rec["local_ip"], rec["local_port"], rec["family"])
    remote = fmt_addr(rec["remote_ip"], rec["remote_port"], rec["family"])
    who = f'{rec["comm"]}[{rec["pid"]}] {rec["user"]}'
    if direction == "outbound":
        line = f'{local_time(rec["ts"])} OUT {who} {local} -> {remote}'
        if rec.get("remote_host"):
            line += f' host={rec["remote_host"]}({rec["remote_host_source"]})'
    else:
        line = f'{local_time(rec["ts"])} IN  {who} {remote} -> {local}'
    if not ARGS.no_cmd and rec.get("cmdline"):
        line += f' cmd={json.dumps(rec["cmdline"], ensure_ascii=False)}'
    return line

def store(direction, rec):
    try:
        LOGGERS[direction].info(format_record(direction, rec))
    except Exception as e:
        print(f"log yazma hatasi ({direction}): {e}", file=sys.stderr, flush=True)

# ------------------------------------------------------------------ eBPF
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define HOST_LEN 256

struct ipv4_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;      // yerel adres
    u32 daddr;      // uzak adres
    u16 sport;      // yerel port
    u16 dport;      // uzak port
    char comm[TASK_COMM_LEN];
};

struct ipv6_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

struct host_event_t {
    u32 pid;
    u32 uid;
    u8 source;   // 1=dns(getaddrinfo), 2=sni(openssl)
    char host[HOST_LEN];
};

BPF_HASH(currsock, u64, struct sock *);
BPF_PERF_OUTPUT(ipv4_out_events);
BPF_PERF_OUTPUT(ipv6_out_events);
BPF_PERF_OUTPUT(ipv4_in_events);
BPF_PERF_OUTPUT(ipv6_in_events);
BPF_PERF_OUTPUT(host_events);

/* ---------------- GIDEN (connect) ---------------- */
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    currsock.update(&pid_tgid, &sk);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) return 0;
    if (ret != 0) { currsock.delete(&pid_tgid); return 0; }

    struct sock *sk = *skpp;
    u16 dport = 0, sport = 0;
    u32 saddr = 0, daddr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);

    struct ipv4_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = ntohs(dport);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    ipv4_out_events.perf_submit(ctx, &evt, sizeof(evt));
    currsock.delete(&pid_tgid);
    return 0;
}

int trace_connect_v6_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) return 0;
    if (ret != 0) { currsock.delete(&pid_tgid); return 0; }

    struct sock *sk = *skpp;
    u16 dport = 0, sport = 0;
    unsigned __int128 saddr = 0, daddr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    struct ipv6_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = ntohs(dport);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    ipv6_out_events.perf_submit(ctx, &evt, sizeof(evt));
    currsock.delete(&pid_tgid);
    return 0;
}

/* ---------------- GELEN (accept) ----------------
   inet_csk_accept donus degeri kabul edilen yeni soket (struct sock *).
   Yerel = hizmeti veren taraf, uzak = baglanan istemci.
   Dual-stack dinleyicide IPv4 istemciler AF_INET6 soket olarak gelir ama
   IPv6 alanlari bos kalir; bu durumda IPv4 olay olarak yazilir. */
int trace_accept_return(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL) return 0;

    u16 family = 0, lport = 0, rport = 0;
    u32 laddr4 = 0, raddr4 = 0;
    unsigned __int128 laddr6 = 0, raddr6 = 0;

    bpf_probe_read_kernel(&family, sizeof(family), &newsk->__sk_common.skc_family);
    bpf_probe_read_kernel(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
    bpf_probe_read_kernel(&rport, sizeof(rport), &newsk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&laddr4, sizeof(laddr4), &newsk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&raddr4, sizeof(raddr4), &newsk->__sk_common.skc_daddr);

    if (family == 10) {
        bpf_probe_read_kernel(&laddr6, sizeof(laddr6), newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&raddr6, sizeof(raddr6), newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    int is_v4 = (family == 2) || (family == 10 && raddr6 == 0 && raddr4 != 0);

    if (is_v4) {
        struct ipv4_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.saddr = laddr4;
        evt.daddr = raddr4;
        evt.sport = lport;
        evt.dport = ntohs(rport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv4_in_events.perf_submit(ctx, &evt, sizeof(evt));
    } else if (family == 10) {
        struct ipv6_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.saddr = laddr6;
        evt.daddr = raddr6;
        evt.sport = lport;
        evt.dport = ntohs(rport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv6_in_events.perf_submit(ctx, &evt, sizeof(evt));
    }
    return 0;
}

/* ---------------- Alan adi tahmini ---------------- */
int trace_getaddrinfo(struct pt_regs *ctx, const char __user *node) {
    if (node == NULL) return 0;
    struct host_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 1;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), node);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_ssl_set_tlsext_host_name(struct pt_regs *ctx, void *ssl, const char __user *name) {
    if (name == NULL) return 0;
    struct host_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 2;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), name);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

class HostEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("source", ct.c_ubyte),
        ("host", ct.c_char * 256),
    ]

# --------------------------------------------------------------- yardimcilar
def ip4_to_str(addr):
    return socket.inet_ntop(socket.AF_INET, int(addr).to_bytes(4, byteorder="little"))

def ip6_to_str(raw):
    try:
        try:
            buf = bytes(raw)
        except Exception:
            buf = int(raw).to_bytes(16, byteorder="big", signed=False)
        if len(buf) != 16:
            buf = buf[:16].ljust(16, b"\x00")
        return socket.inet_ntop(socket.AF_INET6, buf)
    except Exception:
        return ""

def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)

def get_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        return ""

def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return False

def is_private(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return obj.is_private or obj.is_link_local
    except Exception:
        return False

def cleanup_host_cache():
    now = time.time()
    for pid in [p for p, v in HOST_CACHE.items() if now - v["ts"] > HOST_TTL]:
        HOST_CACHE.pop(pid, None)

def remember_host(pid, host, source):
    if not ENABLE_HOST_ENRICHMENT:
        return
    host = (host or "").strip()
    if len(host) < 2 or " " in host or host.startswith("/"):
        return
    HOST_CACHE[pid] = {"host": host, "source": source, "ts": time.time()}

def get_host_for_pid(pid):
    cleanup_host_cache()
    item = HOST_CACHE.get(pid)
    return (item["host"], item["source"]) if item else (None, None)

def should_skip(rec):
    if IGNORE_ROOT and rec["uid"] == 0:
        return True
    if IGNORE_LOOPBACK and is_loopback(rec["local_ip"]) and is_loopback(rec["remote_ip"]):
        return True
    if IGNORE_PRIVATE and is_private(rec["remote_ip"]):
        return True
    return False

def handle_host(cpu, data, size):
    event = ct.cast(data, ct.POINTER(HostEvent)).contents
    pid = int(event.pid)
    source = "dns" if int(event.source) == 1 else "sni"
    host = bytes(event.host).split(b"\x00", 1)[0].decode(errors="replace")
    remember_host(pid, host, source)

# ------------------------------------------------------------- canli cikti
LIVE = not ARGS.quiet
COLOR = sys.stdout.isatty() and not ARGS.no_color
C_OUT, C_IN, C_DIM, C_RESET = ("\033[36m", "\033[33m", "\033[2m", "\033[0m") if COLOR else ("", "", "", "")

BANNER = r"""
▄▄▄▄▄▄▄▄   ▄▄▄▄    ▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄
▄▀░▒▒▓▓█▓▒█▄▀▄░▒▒▒▄ ▀▄░▒░▀▌▀▄░▒▒▒▓█▀▐░▒▒▒▓▓▓█░▄▀▄░▒▒▒▓▓▓█▓▌░▒▒▒▓▓▓█░▄
▌░░░▀▀▀▀▀█▀   ▐░▒▓▒█  ▌░▓█▌  ▐░▒░█   ▐░▒░▀▀▀▐▓░▌ ▐░▒░▀▀▀▒█▐▐░▒░▀▀▀▐▓░▌
▐   ▀▀▀▀▄     ▐▓░▒▓▒▌ ▐▓░█▌  ▐▓ ▓▌   ▐▓ ▐▌ ▄▀▄▀  ▐▓ ▐▄▄▄   ▐▓ ▐▌ ▄▀▄▀
 ▀▄▄▄█▓▓▒▀▄   ▌▒▓█▌█░▄▐▒▓▓█  ▌▒▓▓▌   ▌▒▓▓▀▀▄▀    ▌▒▓▓▒░▌   ▌▒▓▓▀▀░▀▄
▄▄▄▄ ▀▌▒░░▐▌  ▌░ █ ▐░▒░ ░░▌  ▌░ ▐▌   ▌░ ▐▀▀      ▌░ ▐▀▀    ▌░ ▐▀▀▄▓▒█
▐  ▀▄▄▀ ░ █▌ ▐▌  ▐▌ ▀▄ ░ ▐▌  ▌   █   ▐  █        ▌  ▀▄▄▄▀█ ▌  █   █░ █
▐▌      ▄▄▀  █    ▀▄ ▀▄  █ ▄▀  ░▓█▄ ▄█  ▀▄     ▄▀        ▐▄▀  ▀▄ ▄▀   █
 ▀▀▀▀▀▀▀      ▀▀▀▀▀    ▀▀   ▀▀▀▀▀▀  ▀▀▀▀▀▀▀    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀
github.com/faruk-guler www.farukguler.com

"""

def print_banner():
    """Ust yari sari, alt yari kirmizi. Renk yalnizca terminalde ve --no-color yokken."""
    if ARGS.no_banner:
        return
    lines = BANNER.strip("\n").splitlines()
    half = (len(lines) + 1) // 2
    yellow, red, reset = ("\033[93m", "\033[91m", "\033[0m") if COLOR else ("", "", "")
    for i, ln in enumerate(lines):
        print(f"{yellow if i < half else red}{ln.rstrip()}{reset}")
    print(f'{C_DIM}  monitor-only | giden + gelen TCP | Ctrl+C ile durdur{C_RESET}\n', flush=True)

def fmt_addr(ip, port, family):
    return f"[{ip}]:{port}" if family == "ipv6" else f"{ip}:{port}"

def live_print(direction, rec):
    if not LIVE:
        return
    t = datetime.now().strftime("%H:%M:%S")
    local = fmt_addr(rec["local_ip"], rec["local_port"], rec["family"])
    remote = fmt_addr(rec["remote_ip"], rec["remote_port"], rec["family"])
    who = f'{rec["comm"]}[{rec["pid"]}] {rec["user"]}'
    if direction == "outbound":
        line = f'{C_DIM}{t}{C_RESET} {C_OUT}OUT{C_RESET} {who}  {local} -> {remote}'
        if rec.get("remote_host"):
            line += f' ({rec["remote_host"]}, {rec["remote_host_source"]})'
    else:
        line = f'{C_DIM}{t}{C_RESET} {C_IN}IN {C_RESET} {who}  {remote} -> {local}'
    if ARGS.show_cmd and rec.get("cmdline"):
        line += f'  {C_DIM}| {rec["cmdline"][:120]}{C_RESET}'
    print(line, flush=True)

def make_handler(perf_name, direction, family):
    def handler(cpu, data, size):
        try:
            event = b[perf_name].event(data)
            uid = int(event.uid)
            pid = int(event.pid)
            conv = ip4_to_str if family == "ipv4" else ip6_to_str

            rec = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "hostname": HOSTNAME,
                "uid": uid,
                "user": get_username(uid),
                "pid": pid,
                "comm": event.comm.decode(errors="replace").rstrip("\x00"),
                "cmdline": get_cmdline(pid),
                "family": family,
                "local_ip": conv(event.saddr),
                "local_port": int(event.sport),
                "remote_ip": conv(event.daddr),
                "remote_port": int(event.dport),
            }

            if direction == "outbound":
                host, src = get_host_for_pid(pid)
                if host:
                    rec["remote_host"] = host
                    rec["remote_host_source"] = src

            if not should_skip(rec):
                store(direction, rec)
                live_print(direction, rec)
        except Exception as e:
            print(f"handler hatasi ({perf_name}): {e}", file=sys.stderr, flush=True)
    return handler

def find_libssl():
    for path in (
        "/lib64/libssl.so.3", "/lib64/libssl.so.1.1",
        "/usr/lib64/libssl.so.3", "/usr/lib64/libssl.so.1.1",
        "/lib/x86_64-linux-gnu/libssl.so.3", "/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    ):
        if os.path.exists(path):
            return path
    try:
        out = subprocess.check_output(
            ["sh", "-c", "ldconfig -p | grep 'libssl.so' | head -n1 | awk '{print $NF}'"],
            text=True,
        ).strip()
        if out and os.path.exists(out):
            return out
    except Exception:
        pass
    return None

# ---------------------------------------------------------------------- main
def main():
    print_banner()
    LOGGERS["outbound"] = make_logger("sniper.outbound", OUT_LOG)
    LOGGERS["inbound"] = make_logger("sniper.inbound", IN_LOG)

    global b
    b = BPF(text=BPF_PROGRAM)

    for sym in ("tcp_v4_connect", "tcp_v6_connect"):
        b.attach_kprobe(event=sym, fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

    if ENABLE_HOST_ENRICHMENT:
        try:
            b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo")
        except Exception:
            pass
        libssl = find_libssl()
        if libssl:
            try:
                b.attach_uprobe(name=libssl, sym="SSL_set_tlsext_host_name",
                                fn_name="trace_ssl_set_tlsext_host_name")
            except Exception:
                pass

    b["ipv4_out_events"].open_perf_buffer(make_handler("ipv4_out_events", "outbound", "ipv4"))
    b["ipv6_out_events"].open_perf_buffer(make_handler("ipv6_out_events", "outbound", "ipv6"))
    b["ipv4_in_events"].open_perf_buffer(make_handler("ipv4_in_events", "inbound", "ipv4"))
    b["ipv6_in_events"].open_perf_buffer(make_handler("ipv6_in_events", "inbound", "ipv6"))
    b["host_events"].open_perf_buffer(handle_host)

    print(f"sniper basladi (monitor-only, format={ARGS.format}).", flush=True)
    print(f"  giden : {OUT_LOG}", flush=True)
    print(f"  gelen : {IN_LOG}", flush=True)
    print(flush=True)

    try:
        while True:
            b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        pass
    finally:
        logging.shutdown()

signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
main()
