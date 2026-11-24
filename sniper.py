#!/usr/bin/env python3
"""Sniper v0.6: monitor-only. Giden/gelen TCP ile UDP/DNS baglantilarini loglar, engellemez.

Calistirmak icin:  sudo python3 sniper.py
Durdurmak icin:    Ctrl+C
Gereken paketler (Debian/Ubuntu): python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

Formatlar (--format):
  text | txt | log  -> outbound-dump.log / inbound-dump.log   (varsayilan)
  json              -> outbound-dump.json / inbound-dump.json (JSON Lines)
  csv               -> outbound-dump.csv  / inbound-dump.csv  (baslikli CSV)

Kayit turleri (event):
  open      baglanti acildi (giden: connect denemesi, gelen: accept)
  close     baglanti kapandi: sure, bayt (tx/rx) ve sonuc (ok | failed)
  snapshot  Sniper basladiginda zaten acik olan baglanti (yon tahminidir)
  repeat    --dedupe ile bastirilan tekrarlarin ozeti (count alani)
  dns       DNS sorgusu+yaniti tek kayit: ad, tur, rcode, cevaplar, gecikme (proto=udp)
  (UDP akislari 'open' kaydidir ve proto=udp tasir; UDP icin close kaydi yoktur.)

v0.6 yenilikleri:
  * UDP: udp_sendmsg/udpv6_sendmsg ile GIDEN UDP akislari (proto=udp). Cekirdekte (soket,hedef)
    basina --udp-window sn'de en fazla bir kayit (varsayilan 30; DNS portu icin 1 sn).
    UDP icin yalnizca gonderim gorulur: gelen UDP ve yanit akislari izlenmez.
  * DNS: AF_PACKET + klasik BPF suzgeciyle 53/udp sorgu ve yanitlari ayristirilir (surec bilgisi
    UDP akis olayindan eslenir). Yalnizca bu makinenin ucu oldugu trafik: kendi sorgularin
    (outbound) ve bu makinenin cozucu/sunucu oldugu sorgular (inbound; surec bilinmez).
    DNS-over-TCP/TLS/HTTPS, mDNS ve 53 disi portlar gorulmez; IP parcalanmis buyuk yanitlar eksik
    ayristirilabilir. systemd-resolved varsa hem uygulama->127.0.0.53 hem cozucu->yukari akis
    ayri kayit olarak gorunur.
  * host_guess artik DNS yanitlarindan da beslenir: sni > dns-resp (surec+IP eslesmesi) >
    dns (getaddrinfo) > dns-ip (yalniz IP eslesmesi).
  * Olaylar (BPF + DNS paketleri) olay zamanina gore siralanip ~0.3 sn gecikmeyle islenir.
  * Yeni bayraklar: --no-udp, --no-dns, --udp-window.

v0.5 yenilikleri:
  * Yasam dongusu: close kayitlari (sure, bayt, sonuc). Gelen baglantilarda sure
    accept anindan baslar. bytes_tx = karsi tarafca onaylanan bayt, bytes_rx = alinan bayt.
    Cekirdek tracepoint'i veya bayt sayaclari yoksa otomatik daha dar moda dusulur.
  * Baslangic anlik goruntusu: /proc/net/tcp* + /proc/*/fd ile acik baglantilar.
    Yon, yerel portun dinleyen bir port olup olmadigina gore TAHMIN edilir; yalnizca
    ana ag ad alani (host netns) taranir; bu baglantilar icin close kaydi uretilmez.
  * Zenginlestirme: ppid, exe, unit (systemd), container (docker/containerd/crio/podman/lxc).
  * Kurallar: --config kurallar.json, --ignore-comm, --ignore-port; --dedupe SN.
  * Olaylar BPF zaman damgasina gore siralanarak islenir; zaman damgasi olay anidir.

Kural dosyasi (JSON, ilk eslesen kazanir; bir kuraldaki tum alanlar VE, listeler VEYA):
  {
    "default": "log",
    "rules": [
      {"action": "ignore", "comm": ["chronyd"], "port": [123]},
      {"action": "ignore", "direction": "outbound", "remote_cidr": ["10.0.0.0/8"], "port": ["53"]}
    ]
  }
  Alanlar: action(log|ignore) direction(out|in) uid comm exe user unit container host proto event
           (fnmatch desenleri) port remote_port local_port (sayi veya "a-b")
           remote_cidr local_cidr. "port" hizmet tarafidir (giden: uzak, gelen: yerel).

Notlar:
  * "outbound" open kayitlari baglanti DENEMESIDIR; sonucu close kaydindaki outcome gosterir
    (failed = hic ESTABLISHED olmadi). connect() hemen hata donerse kayit uretilmez.
  * host_guess alani bir TAHMINDIR: ayni PID'nin son DNS (getaddrinfo) / SNI
    (OpenSSL) adi, 20 sn icinde eslestirilir. Ayni surec birden fazla ad cozerse
    yanlis eslesebilir. Kendi TLS kutuphanesini gomen programlar (Go, Node,
    Chrome...) SNI kapsaminda degildir.
  * Komut satiri varsayilan olarak KAPALIDIR (parola icerebilir); --cmd ile acilir.
  * Sema genisledi: v0.5 (event, ppid, exe, unit, container, duration_ms, bytes_tx, bytes_rx,
    outcome, count), v0.6 (proto, dns_name, dns_type, dns_rcode, dns_answers, dns_ms, dns_tc).
    v0.4'ten: remote_host -> host_guess, remote_host_source -> host_guess_source.
  * DNS kayitlarinda 'host' kurali dns_name'e uygulanir; DNS kayitlari --log-loopback/--ignore-private
    suzgeclerinden etkilenmez (cozucu genelde yerel/ozeldir); suzmek icin kurallari kullan.
  * 'host' bos ve pid=0 olan DNS kaydi: cozumleyen surec belirlenemedi (inbound, ya da UDP akis
    olayi yakalanamadi).
"""
import os
import re
import sys
import pwd
import csv
import io
import json
import time
import signal
import socket
import fnmatch
import heapq
import struct
import ctypes as ct
import logging
import logging.handlers
import argparse
import ipaddress
import subprocess
from collections import OrderedDict
from datetime import datetime, timezone

VERSION = "0.6"


def warn(msg):
    print(f"sniper uyari: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ argumanlar
FORMAT_ALIASES = {
    "text": "text", "txt": "text", "log": "text",
    "json": "json",
    "csv": "csv",
}
FILE_EXT = {"text": "log", "json": "json", "csv": "csv"}

parser = argparse.ArgumentParser(
    description="Sniper: eBPF ile giden/gelen TCP baglanti izleme ve kayit (monitor-only)")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
parser.add_argument("--log-dir", default=SCRIPT_DIR,
                    help="Log dizini (varsayilan: betigin bulundugu dizin)")
parser.add_argument("--format", choices=tuple(FORMAT_ALIASES), default="text",
                    help="Log bicimi: text/txt/log (varsayilan), json (JSON Lines), csv")
parser.add_argument("--cmd", action="store_true",
                    help="Komut satirini oku ve kaydet (varsayilan KAPALI; parola icerebilir)")
parser.add_argument("--no-cmd", action="store_true",
                    help="Geriye uyumluluk: komut satiri zaten varsayilan olarak kapali; --cmd'yi gecersiz kilar")
parser.add_argument("--max-mb", type=int, default=50,
                    help="Bir log dosyasinin azami boyutu, MB (asinca donusum yapilir)")
parser.add_argument("--backups", type=int, default=5,
                    help="Saklanacak eski log dosyasi sayisi (.1, .2, ...)")
parser.add_argument("--log-loopback", action="store_true",
                    help="127.0.0.1 <-> 127.0.0.1 baglantilari da kaydet")
parser.add_argument("--ignore-private", action="store_true",
                    help="GIDEN baglantilarda hedefi ozel IP (10.x, 192.168.x, fc00::/7...) olanlari atla")
parser.add_argument("--ignore-private-inbound", action="store_true",
                    help="GELEN baglantilarda istemcisi ozel IP olanlari atla (sunucuda LAN trafigini gizler)")
parser.add_argument("--ignore-root", action="store_true",
                    help="root kullanicisinin baglantilarini atla")
parser.add_argument("--no-host", action="store_true",
                    help="Alan adi tahminini (DNS/SNI) kapat")
parser.add_argument("--no-lifecycle", action="store_true",
                    help="Kapanis kayitlarini (sure, bayt, sonuc) kapat")
parser.add_argument("--no-bytes", action="store_true",
                    help="Kapanis kaydinda bayt sayaclarini okuma (eski cekirdekler icin)")
parser.add_argument("--no-snapshot", action="store_true",
                    help="Baslangicta acik baglantilarin anlik goruntusunu alma")
parser.add_argument("--no-udp", action="store_true",
                    help="Giden UDP akislarini (udp_sendmsg) izleme")
parser.add_argument("--no-dns", action="store_true",
                    help="DNS (53/udp) paket yakalama ve ayristirmayi kapat")
parser.add_argument("--udp-window", type=float, default=30.0, metavar="SN",
                    help="Ayni (soket, hedef) UDP akisi icin kayitlar arasi en az sure, sn "
                         "(varsayilan 30; 0 = her gonderim, cok kayit uretir)")
parser.add_argument("--no-enrich", action="store_true",
                    help="ppid/exe/unit/container zenginlestirmesini kapat (daha az /proc okuma)")
parser.add_argument("--config", metavar="DOSYA",
                    help="JSON filtre kurallari dosyasi (ornek: sniper-rules.example.json)")
parser.add_argument("--ignore-comm", action="append", default=[], metavar="DESEN",
                    help="Program adi (fnmatch) eslesen baglantilari atla; tekrarlanabilir")
parser.add_argument("--ignore-port", action="append", default=[], type=int, metavar="PORT",
                    help="Hizmet portu (giden: uzak, gelen: yerel) eslesenleri atla; tekrarlanabilir")
parser.add_argument("--dedupe", type=float, default=0.0, metavar="SN",
                    help="Ayni (surec, hedef IP, hizmet portu) icin SN saniye icindeki tekrar acilislari "
                         "bastir ve ozet 'repeat' kaydi yaz (0 = kapali)")
parser.add_argument("--perf-pages", type=int, default=64,
                    help="CPU basina perf tampon sayfasi, 2'nin kuvveti (varsayilan 64; olay kaybi olursa artirin)")
parser.add_argument("--quiet", action="store_true",
                    help="Canli ekran ciktisini kapat (yalnizca log dosyasina yaz)")
parser.add_argument("--show-cmd", action="store_true",
                    help="Canli ciktida komut satirini da goster (--cmd gerektirir; parola icerebilir)")
parser.add_argument("--no-color", action="store_true", help="Canli ciktida renkleri kapat")
parser.add_argument("--no-banner", action="store_true", help="Acilis bannerini gosterme")
parser.add_argument("--csv-delimiter", choices=(",", ";", "|", "tab"), default=",",
                    help="CSV ayiraci (Turkce Excel icin ';' onerilir, varsayilan ',')")
parser.add_argument("--csv-bom", action="store_true",
                    help="Yeni CSV dosyalarina UTF-8 BOM yaz (Excel'de Turkce karakterler icin)")
parser.add_argument("--csv-excel-safe", action="store_true",
                    help="CSV'de =,+,-,@ ile baslayan hucreleri ' ile onekleyerek formul enjeksiyonunu onle")
ARGS = parser.parse_args()
ARGS.format = FORMAT_ALIASES[ARGS.format]
if ARGS.perf_pages < 1 or (ARGS.perf_pages & (ARGS.perf_pages - 1)):
    parser.error("--perf-pages 2'nin kuvveti olmali (ornek: 8, 16, 64, 128)")
if ARGS.dedupe < 0:
    parser.error("--dedupe negatif olamaz")
if ARGS.udp_window < 0:
    parser.error("--udp-window negatif olamaz")
# Komut satiri yalnizca --cmd verildiyse ve --no-cmd verilmediyse acik.
ARGS.no_cmd = ARGS.no_cmd or not ARGS.cmd

# Root kontrolu ve bcc importu argumanlardan sonra: --help root istemez.
if os.geteuid() != 0:
    print("Sniper root olarak calistirilmalidir: sudo python3 sniper.py", file=sys.stderr)
    sys.exit(1)

try:
    from bcc import BPF
except Exception as e:
    print(f"BCC import hatasi: {e}\nKurulum: sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)",
          file=sys.stderr)
    sys.exit(1)

LOG_DIR = os.path.abspath(ARGS.log_dir)
IGNORE_LOOPBACK = not ARGS.log_loopback
IGNORE_PRIVATE_OUT = ARGS.ignore_private
IGNORE_PRIVATE_IN = ARGS.ignore_private_inbound
IGNORE_ROOT = ARGS.ignore_root
ENABLE_HOST_ENRICHMENT = not ARGS.no_host
ENRICH = not ARGS.no_enrich
HOSTNAME = socket.gethostname()

EXT = FILE_EXT[ARGS.format]
OUT_LOG = os.path.join(LOG_DIR, f"outbound-dump.{EXT}")
IN_LOG = os.path.join(LOG_DIR, f"inbound-dump.{EXT}")

# Yeni olusan log dosyalari yalnizca root + grup tarafindan okunabilsin (640)
os.umask(0o027)

b = None                 # BPF nesnesi (main'de olusur)
LIFECYCLE_ON = False     # close kayitlari gercekten uretiliyor mu (derleme sonucu)
BYTES_ON = False         # bayt sayaclari okunuyor mu (derleme sonucu)
UDP_ON = False           # UDP kprobe'lari baglandi mi
DNS_ON = False           # DNS paket yakalama calisiyor mu

HOST_CACHE = {}
HOST_TTL = 20
_HOST_GC_LAST = 0.0
_UID_CACHE = {}

# Kontrol karakterleri (C0, DEL, C1, satir/paragraf ayiricilari): log satiri sahteciligi
# ve terminal kacis dizisi (ESC) enjeksiyonuna karsi.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
# Gecerli sayilan alan adi/IP metni (harf, rakam, '.', '-', '_', ':')
_HOST_RE = re.compile(r"[A-Za-z0-9._:-]{2,253}")


def sanitize(value):
    """Kontrol karakterlerini bosluga cevirir."""
    if not value:
        return value
    return _CTRL_RE.sub(" ", value)


# ------------------------------------------------------------------ CSV sabitleri
CSV_DELIM = "\t" if ARGS.csv_delimiter == "tab" else ARGS.csv_delimiter
CSV_COLUMNS = [
    "ts", "hostname", "event", "proto", "direction", "uid", "user", "pid", "ppid", "comm",
    "exe", "unit", "container",
    "family", "local_ip", "local_port", "remote_ip", "remote_port",
    "host_guess", "host_guess_source",
    "duration_ms", "bytes_tx", "bytes_rx", "outcome", "count",
    "dns_name", "dns_type", "dns_rcode", "dns_answers", "dns_ms", "dns_tc",
]
if not ARGS.no_cmd:
    CSV_COLUMNS.append("cmdline")


def _csv_line(values):
    buf = io.StringIO()
    csv.writer(buf, delimiter=CSV_DELIM, quoting=csv.QUOTE_MINIMAL,
               lineterminator="").writerow(values)
    return buf.getvalue()


CSV_HEADER = _csv_line(CSV_COLUMNS)


def csv_cell(value):
    """CSV hucre guvenligi: satir sonlarini temizle, istenirse formul enjeksiyonunu onle."""
    if value is None:
        return ""
    s = str(value)
    if "\n" in s or "\r" in s or "\t" in s:
        s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if ARGS.csv_excel_safe and s[:1] in ("=", "+", "-", "@"):
        s = "'" + s
    return s


# ------------------------------------------------------------- log dosyalari
class CsvRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Bos (yeni olusturulmus veya rotate edilmis) CSV dosyasina baslik yazar."""

    def _open(self):
        stream = super()._open()
        try:
            if stream.tell() == 0:
                stream.write(("﻿" if ARGS.csv_bom else "") + CSV_HEADER + "\n")
                stream.flush()
        except Exception:
            pass
        return stream


def make_logger(name, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    kwargs = dict(maxBytes=max(ARGS.max_mb, 1) * 1024 * 1024,
                  backupCount=max(ARGS.backups, 0), encoding="utf-8")
    if ARGS.format == "csv":
        handler = CsvRotatingFileHandler(path, **kwargs)
    else:
        handler = logging.handlers.RotatingFileHandler(path, **kwargs)
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


def human_bytes(n):
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{int(n)}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0


def human_dur(ms):
    if ms is None:
        return "?"
    if ms < 1000:
        return f"{ms:.0f}ms"
    s = ms / 1000.0
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    if m < 60:
        return f"{m}m{sec:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def fmt_addr(ip, port, family):
    return f"[{ip}]:{port}" if family == "ipv6" else f"{ip}:{port}"


def _path_str(direction, rec):
    local = fmt_addr(rec["local_ip"], rec["local_port"], rec["family"])
    remote = fmt_addr(rec["remote_ip"], rec["remote_port"], rec["family"])
    return f"{local} -> {remote}" if direction == "outbound" else f"{remote} -> {local}"


def _who(rec):
    if rec.get("pid"):
        return f'{rec["comm"]}[{rec["pid"]}] {rec["user"]}'
    return rec.get("comm") or "-"


def _tail(rec):
    s = ""
    if rec.get("ppid") is not None:
        s += f' ppid={rec["ppid"]}'
    if rec.get("exe"):
        s += f' exe={json.dumps(rec["exe"], ensure_ascii=False)}'
    if rec.get("unit"):
        s += f' unit={rec["unit"]}'
    if rec.get("container"):
        s += f' ctr={rec["container"]}'
    if not ARGS.no_cmd and rec.get("cmdline"):
        s += f' cmd={json.dumps(rec["cmdline"], ensure_ascii=False)}'
    return s


def format_record(direction, rec):
    out = dict(rec)
    out["direction"] = direction
    if ARGS.no_cmd:
        out.pop("cmdline", None)

    if ARGS.format == "json":
        return json.dumps(out, ensure_ascii=False, separators=(",", ":"))

    if ARGS.format == "csv":
        if isinstance(out.get("dns_answers"), list):
            out["dns_answers"] = " ".join(out["dns_answers"])
        if "dns_tc" in out:
            out["dns_tc"] = int(bool(out["dns_tc"]))
        return _csv_line([csv_cell(out.get(col)) for col in CSV_COLUMNS])

    # text (varsayilan) -- tum degiskenler kayit olusturulurken sanitize edildi
    evt = rec.get("event", "open")
    out_dir = direction == "outbound"
    udp = rec.get("proto") == "udp"
    if evt == "dns":
        head = "DNS" if out_dir else "DNS-IN"
    elif evt == "open":
        head = ("OUT-UDP" if out_dir else "IN-UDP") if udp else ("OUT" if out_dir else "IN ")
    else:
        head = f'{"OUT" if out_dir else "IN"}-{evt.upper()}'
    line = f'{local_time(rec["ts"])} {head} {_who(rec)} {_path_str(direction, rec)}'
    if evt == "dns":
        ans = ",".join(rec.get("dns_answers") or [])
        line += f' {rec.get("dns_type")} {rec.get("dns_name")}'
        if ans:
            line += f' => {ans}'
        line += f' rcode={rec.get("dns_rcode")}'
        if rec.get("dns_ms") is not None:
            line += f' time={human_dur(rec["dns_ms"])}'
        if rec.get("dns_tc"):
            line += " tc"
    else:
        if out_dir and rec.get("host_guess"):
            line += f' host_guess={rec["host_guess"]}({rec["host_guess_source"]})'
        if evt == "close":
            line += (f' dur={human_dur(rec.get("duration_ms"))} tx={human_bytes(rec.get("bytes_tx"))}'
                     f' rx={human_bytes(rec.get("bytes_rx"))} outcome={rec.get("outcome")}')
        elif evt == "repeat":
            line += f' repeated={rec.get("count")}'
            if rec.get("dns_name"):
                line += f' {rec.get("dns_type")} {rec.get("dns_name")}'
    return line + _tail(rec)


def store(direction, rec):
    try:
        LOGGERS[direction].info(format_record(direction, rec))
    except Exception as e:
        print(f"log yazma hatasi ({direction}): {e}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ filtre kurallari
def _as_list(v):
    return v if isinstance(v, list) else [v]


def _parse_ports(v):
    out = []
    for item in _as_list(v):
        if isinstance(item, bool):
            raise ValueError(f"gecersiz port: {item!r}")
        if isinstance(item, int):
            out.append((item, item))
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", str(item).strip())
        if not m:
            raise ValueError(f"gecersiz port: {item!r}")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        out.append((lo, hi))
    return out


_TEXT_FIELDS = ("comm", "exe", "user", "unit", "container", "host", "proto", "event")
_PORT_FIELDS = ("port", "remote_port", "local_port")
_CIDR_FIELDS = ("remote_cidr", "local_cidr")
_RULE_KEYS = {"action", "direction", "uid"} | set(_TEXT_FIELDS) | set(_PORT_FIELDS) | set(_CIDR_FIELDS)
_DIRECTIONS = {"out": "outbound", "outbound": "outbound", "in": "inbound", "inbound": "inbound"}


class Rule:
    """Tek bir filtre kurali: belirtilen tum alanlar eslesirse (VE) action gecerli olur."""

    def __init__(self, spec):
        unknown = set(spec) - _RULE_KEYS
        if unknown:
            raise ValueError(f"bilinmeyen anahtar: {', '.join(sorted(unknown))}")
        self.action = spec.get("action", "log")
        if self.action not in ("log", "ignore"):
            raise ValueError(f"gecersiz action: {self.action!r} (log|ignore)")
        d = spec.get("direction")
        if d is None:
            self.direction = None
        else:
            key = str(d).lower()
            if key not in _DIRECTIONS:
                raise ValueError(f"gecersiz direction: {d!r}")
            self.direction = _DIRECTIONS[key]
        self.uids = [int(x) for x in _as_list(spec["uid"])] if "uid" in spec else None
        self.text = {k: [str(x) for x in _as_list(spec[k])] for k in _TEXT_FIELDS if k in spec}
        self.ports = {k: _parse_ports(spec[k]) for k in _PORT_FIELDS if k in spec}
        self.cidrs = {k: [ipaddress.ip_network(str(x), strict=False) for x in _as_list(spec[k])]
                      for k in _CIDR_FIELDS if k in spec}

    def matches(self, direction, rec):
        if self.direction is not None and self.direction != direction:
            return False
        if self.uids is not None and rec["uid"] not in self.uids:
            return False
        for key, patterns in self.text.items():
            if key == "host":
                val = (rec.get("dns_name") if rec.get("event") == "dns" else rec.get("host_guess")) or ""
            else:
                val = rec.get(key) or ""
            if not any(fnmatch.fnmatchcase(val, p) for p in patterns):
                return False
        for key, ranges in self.ports.items():
            if key == "port":
                port = rec["remote_port"] if direction == "outbound" else rec["local_port"]
            else:
                port = rec[key]
            if not any(lo <= port <= hi for lo, hi in ranges):
                return False
        for key, nets in self.cidrs.items():
            try:
                addr = _ip_obj(rec["remote_ip" if key == "remote_cidr" else "local_ip"])
            except ValueError:
                return False
            if not any(addr in n for n in nets):
                return False
        return True


def load_rules(path):
    """Komut satiri kurallari + (varsa) JSON dosyasi. Doner: (kurallar, varsayilan eylem)."""
    rules = []
    for pat in ARGS.ignore_comm:
        rules.append(Rule({"action": "ignore", "comm": [pat]}))
    for port in ARGS.ignore_port:
        rules.append(Rule({"action": "ignore", "port": [port]}))
    default = "log"
    if path:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError("kok oge bir nesne olmali")
        extra = set(cfg) - {"default", "rules"}
        if extra:
            raise ValueError(f"bilinmeyen ust duzey anahtar: {', '.join(sorted(extra))}")
        default = cfg.get("default", "log")
        if default not in ("log", "ignore"):
            raise ValueError(f"gecersiz default: {default!r} (log|ignore)")
        specs = cfg.get("rules", [])
        if not isinstance(specs, list):
            raise ValueError("'rules' bir liste olmali")
        for i, spec in enumerate(specs, 1):
            if not isinstance(spec, dict):
                raise ValueError(f"kural #{i}: nesne olmali")
            try:
                rules.append(Rule(spec))
            except (ValueError, KeyError, TypeError) as e:
                raise ValueError(f"kural #{i}: {e}") from None
    return rules, default


try:
    RULES, RULES_DEFAULT = load_rules(ARGS.config)
except (OSError, ValueError) as e:      # json.JSONDecodeError de ValueError'dur
    print(f"Kural hatasi: {e}", file=sys.stderr)
    sys.exit(2)


def rules_action(direction, rec):
    for r in RULES:
        if r.matches(direction, rec):
            return r.action
    return RULES_DEFAULT


# ------------------------------------------------------------------ eBPF
BPF_PROGRAM = r"""
#define KBUILD_MODNAME "sniper"
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define HOST_LEN 256

/* TCP durumlari (net/tcp_states.h'a bagimli olmamak icin) */
#define ST_ESTABLISHED 1
#define ST_SYN_SENT    2
#define ST_SYN_RECV    3
#define ST_CLOSE       7

/* IPv4-mapped IPv6 (::ffff:a.b.c.d): bellekteki bayt dizisi 00*10 ff ff a b c d.
   u32[4] olarak okununca [0]==0, [1]==0, [2]==ff ff 00 00 (little-endian) ve
   [3] ag bayt sirasinda IPv4 adrestir (skc_daddr ile ayni gosterim). */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define V4MAP_MARK 0xffff0000u
#else
#define V4MAP_MARK 0x0000ffffu
#endif
#define IS_V4MAPPED(a) ((a)[0] == 0 && (a)[1] == 0 && (a)[2] == V4MAP_MARK)
#define COPY6(d, s) do { (d)[0] = (s)[0]; (d)[1] = (s)[1]; (d)[2] = (s)[2]; (d)[3] = (s)[3]; } while (0)

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0

struct ipv4_event_t {
    u64 ts_us;
    u64 sk;         // soket adresi (yalnizca eslestirme anahtari)
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
    u64 sk;
    u32 pid;
    u32 uid;
    u32 saddr[4];
    u32 daddr[4];
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

struct host_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u8 source;   // 1=dns(getaddrinfo), 2=sni(openssl)
    char host[HOST_LEN];
};

/* Acilista olusturulan, kapanista okunan baglanti kaydi */
struct conn_t {
    u64 start_ns;
    u32 pid;
    u32 uid;
    u32 saddr[4];
    u32 daddr[4];
    u16 sport;
    u16 dport;
    u16 family;         // 2 = IPv4 (adres [0]'da), 10 = IPv6
    u8 dir;             // 1 = giden, 2 = gelen
    u8 established;
    char comm[TASK_COMM_LEN];
};

struct close_event_t {
    u64 ts_us;
    u64 sk;
    u64 dur_us;
    u64 tx_bytes;
    u64 rx_bytes;
    u32 pid;
    u32 uid;
    u32 saddr[4];
    u32 daddr[4];
    u16 sport;
    u16 dport;
    u16 family;
    u8 dir;
    u8 established;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(currsock, u64, struct sock *);
BPF_PERF_OUTPUT(ipv4_out_events);
BPF_PERF_OUTPUT(ipv6_out_events);
BPF_PERF_OUTPUT(ipv4_in_events);
BPF_PERF_OUTPUT(ipv6_in_events);
BPF_PERF_OUTPUT(host_events);

#ifndef NO_LIFECYCLE
BPF_TABLE("lru_hash", u64, struct conn_t, conns, 65536);
BPF_PERF_OUTPUT(close_events);

/* st: soketin o andaki TCP durumu. Handshake connect() donusunden once bittiyse
   (ornegin loopback) ESTABLISHED gecisi kacirilmis olur; bunu durumdan anlariz. */
static __always_inline void track4(u64 sk, u32 pid, u32 uid, u32 saddr, u32 daddr,
                                   u16 sport, u16 dport, u8 dir, u8 st) {
    if (st == ST_CLOSE) return;
    struct conn_t c = {};
    c.start_ns = bpf_ktime_get_ns();
    c.pid = pid;
    c.uid = uid;
    c.saddr[0] = saddr;
    c.daddr[0] = daddr;
    c.sport = sport;
    c.dport = dport;
    c.family = 2;
    c.dir = dir;
    c.established = (st != ST_SYN_SENT && st != ST_SYN_RECV);
    bpf_get_current_comm(&c.comm, sizeof(c.comm));
    conns.update(&sk, &c);
}

static __always_inline void track6(u64 sk, u32 pid, u32 uid, u32 *s, u32 *d,
                                   u16 sport, u16 dport, u8 dir, u8 st) {
    if (st == ST_CLOSE) return;
    struct conn_t c = {};
    c.start_ns = bpf_ktime_get_ns();
    c.pid = pid;
    c.uid = uid;
    COPY6(c.saddr, s);
    COPY6(c.daddr, d);
    c.sport = sport;
    c.dport = dport;
    c.family = 10;
    c.dir = dir;
    c.established = (st != ST_SYN_SENT && st != ST_SYN_RECV);
    bpf_get_current_comm(&c.comm, sizeof(c.comm));
    conns.update(&sk, &c);
}
#else
#define track4(...) do { } while (0)
#define track6(...) do { } while (0)
#endif

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
    u8 st = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&st, sizeof(st), (void *)&sk->__sk_common.skc_state);

    struct ipv4_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.sk = (u64)sk;
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.saddr = saddr;
    evt.daddr = daddr;
    evt.sport = sport;
    evt.dport = ntohs(dport);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    ipv4_out_events.perf_submit(ctx, &evt, sizeof(evt));
    track4((u64)sk, evt.pid, evt.uid, saddr, daddr, sport, evt.dport, 1, st);
    currsock.delete(&pid_tgid);
    return 0;
}

/* Not: AF_INET6 soketten v4-mapped adrese connect edilirse cekirdek icerde
   tcp_v4_connect'i cagirir; o donus once calisip kaydi yazar ve currsock
   girdisini siler, boylece buraya dusmez. Asagidaki v4-mapped dali yalniz
   guvenlik agi olarak durur (cift kayit olusmaz). */
int trace_connect_v6_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) return 0;
    if (ret != 0) { currsock.delete(&pid_tgid); return 0; }

    struct sock *sk = *skpp;
    u16 dport = 0, sport = 0;
    u32 s4 = 0;
    u8 st = 0;
    u32 s6[4] = {}, d6[4] = {};

    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&s4, sizeof(s4), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&st, sizeof(st), (void *)&sk->__sk_common.skc_state);
    bpf_probe_read_kernel(&s6, sizeof(s6), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&d6, sizeof(d6), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    if (IS_V4MAPPED(d6)) {
        struct ipv4_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.sk = (u64)sk;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        evt.saddr = IS_V4MAPPED(s6) ? s6[3] : s4;
        evt.daddr = d6[3];
        evt.sport = sport;
        evt.dport = ntohs(dport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv4_out_events.perf_submit(ctx, &evt, sizeof(evt));
        track4((u64)sk, evt.pid, evt.uid, evt.saddr, evt.daddr, sport, evt.dport, 1, st);
    } else {
        struct ipv6_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.sk = (u64)sk;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        COPY6(evt.saddr, s6);
        COPY6(evt.daddr, d6);
        evt.sport = sport;
        evt.dport = ntohs(dport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv6_out_events.perf_submit(ctx, &evt, sizeof(evt));
        track6((u64)sk, evt.pid, evt.uid, s6, d6, sport, evt.dport, 1, st);
    }
    currsock.delete(&pid_tgid);
    return 0;
}

/* ---------------- GELEN (accept) ----------------
   inet_csk_accept donus degeri kabul edilen yeni soket (struct sock *).
   Yerel = hizmeti veren taraf, uzak = baglanan istemci.
   Dual-stack dinleyicide IPv4 istemciler AF_INET6 soket olarak gelir ve
   skc_v6_daddr '::ffff:a.b.c.d' (v4-mapped) olarak DOLU olur; bu durumda
   olay IPv4 olarak yazilir. */
int trace_accept_return(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL) return 0;

    u16 family = 0, lport = 0, rport = 0;
    u32 laddr4 = 0, raddr4 = 0;
    u8 st = 0;
    u32 l6[4] = {}, r6[4] = {};

    bpf_probe_read_kernel(&family, sizeof(family), &newsk->__sk_common.skc_family);
    bpf_probe_read_kernel(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
    bpf_probe_read_kernel(&rport, sizeof(rport), &newsk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&laddr4, sizeof(laddr4), &newsk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&raddr4, sizeof(raddr4), &newsk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&st, sizeof(st), (void *)&newsk->__sk_common.skc_state);

    if (family == 10) {
        bpf_probe_read_kernel(&l6, sizeof(l6), newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&r6, sizeof(r6), newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    int mapped = (family == 10) && IS_V4MAPPED(r6);

    if (family == 2 || mapped) {
        struct ipv4_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.sk = (u64)newsk;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        if (mapped) {
            evt.saddr = IS_V4MAPPED(l6) ? l6[3] : laddr4;
            evt.daddr = r6[3] ? r6[3] : raddr4;
        } else {
            evt.saddr = laddr4;
            evt.daddr = raddr4;
        }
        evt.sport = lport;
        evt.dport = ntohs(rport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv4_in_events.perf_submit(ctx, &evt, sizeof(evt));
        track4((u64)newsk, evt.pid, evt.uid, evt.saddr, evt.daddr, lport, evt.dport, 2, st);
    } else if (family == 10) {
        struct ipv6_event_t evt = {};
        evt.ts_us = bpf_ktime_get_ns() / 1000;
        evt.sk = (u64)newsk;
        evt.pid = pid_tgid >> 32;
        evt.uid = bpf_get_current_uid_gid();
        COPY6(evt.saddr, l6);
        COPY6(evt.daddr, r6);
        evt.sport = lport;
        evt.dport = ntohs(rport);
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        ipv6_in_events.perf_submit(ctx, &evt, sizeof(evt));
        track6((u64)newsk, evt.pid, evt.uid, l6, r6, lport, evt.dport, 2, st);
    }
    return 0;
}

#ifndef NO_LIFECYCLE
/* ---------------- Yasam dongusu: ESTABLISHED / CLOSE ---------------- */
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP) return 0;
    u64 key = (u64)args->skaddr;
    int ns = args->newstate;

    if (ns == ST_ESTABLISHED) {
        struct conn_t *ce = conns.lookup(&key);
        if (ce) ce->established = 1;
        return 0;
    }
    if (ns != ST_CLOSE) return 0;

    struct conn_t *c = conns.lookup(&key);
    if (c == 0) return 0;

    u64 now = bpf_ktime_get_ns();
    struct close_event_t evt = {};
    evt.ts_us = now / 1000;
    evt.sk = key;
    evt.dur_us = (now - c->start_ns) / 1000;
    evt.pid = c->pid;
    evt.uid = c->uid;
    COPY6(evt.saddr, c->saddr);
    COPY6(evt.daddr, c->daddr);
    evt.sport = c->sport;
    evt.dport = c->dport;
    evt.family = c->family;
    evt.dir = c->dir;
    evt.established = c->established;
    __builtin_memcpy(evt.comm, c->comm, sizeof(evt.comm));
#ifndef NO_BYTES
    struct sock *sk = (struct sock *)args->skaddr;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    bpf_probe_read_kernel(&evt.rx_bytes, sizeof(evt.rx_bytes), &tp->bytes_received);
    bpf_probe_read_kernel(&evt.tx_bytes, sizeof(evt.tx_bytes), &tp->bytes_acked);
#endif
    close_events.perf_submit(args, &evt, sizeof(evt));
    conns.delete(&key);
    return 0;
}
#endif

#ifndef NO_UDP
/* ---------------- GIDEN UDP (udp_sendmsg / udpv6_sendmsg) ----------------
   msghdr'in ilk alani msg_name'dir; sockaddr_in: family@0 port@2 addr@4,
   sockaddr_in6: family@0 port@2 addr@8. Yalnizca ilk gonderim (pencere) kaydedilir.
   AF_INET6 soketten v4-mapped/AF_INET hedefe gonderim cekirdekte udp_sendmsg'e duser;
   v6 probe bunlari atlar, boylece cift kayit olusmaz. */
#ifndef UDP_WINDOW_NS
#define UDP_WINDOW_NS 30000000000ULL
#endif
#ifndef UDP_DNS_WINDOW_NS
#define UDP_DNS_WINDOW_NS 1000000000ULL
#endif

struct udp_pend_t {
    u64 t0_ns;
    u64 sk;
    u32 daddr[4];
    u16 dport;      // ag bayt sirasi
    u16 family;     // 2 | 10
};

struct udp_key_t {
    u64 sk;
    u32 daddr[4];
    u16 dport;
    u16 pad0;
    u32 pad1;
};

struct udp_event_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr[4];
    u32 daddr[4];
    u16 sport;
    u16 dport;
    u16 family;
    u16 pad;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(udp_pending, u64, struct udp_pend_t);
BPF_TABLE("lru_hash", struct udp_key_t, u64, udp_seen, 32768);
BPF_PERF_OUTPUT(udp_events);

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, void *msg) {
    struct udp_pend_t p = {};
    void *name = NULL;
    bpf_probe_read_kernel(&name, sizeof(name), msg);
    if (name != NULL) {
        u16 fam = 0;
        bpf_probe_read_kernel(&fam, sizeof(fam), name);
        if (fam != 2) return 0;
        bpf_probe_read_kernel(&p.dport, sizeof(p.dport), (char *)name + 2);
        bpf_probe_read_kernel(&p.daddr[0], 4, (char *)name + 4);
    } else {
        bpf_probe_read_kernel(&p.dport, sizeof(p.dport), &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&p.daddr[0], 4, &sk->__sk_common.skc_daddr);
    }
    if (p.daddr[0] == 0 || p.dport == 0) return 0;
    p.family = 2;
    p.sk = (u64)sk;
    p.t0_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    udp_pending.update(&pid_tgid, &p);
    return 0;
}

int trace_udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk, void *msg) {
    struct udp_pend_t p = {};
    void *name = NULL;
    bpf_probe_read_kernel(&name, sizeof(name), msg);
    if (name != NULL) {
        u16 fam = 0;
        bpf_probe_read_kernel(&fam, sizeof(fam), name);
        if (fam != 10) return 0;
        bpf_probe_read_kernel(&p.dport, sizeof(p.dport), (char *)name + 2);
        bpf_probe_read_kernel(&p.daddr, sizeof(p.daddr), (char *)name + 8);
    } else {
        bpf_probe_read_kernel(&p.dport, sizeof(p.dport), &sk->__sk_common.skc_dport);
        bpf_probe_read_kernel(&p.daddr, sizeof(p.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    if (IS_V4MAPPED(p.daddr)) return 0;
    if ((p.daddr[0] | p.daddr[1] | p.daddr[2] | p.daddr[3]) == 0 || p.dport == 0) return 0;
    p.family = 10;
    p.sk = (u64)sk;
    p.t0_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    udp_pending.update(&pid_tgid, &p);
    return 0;
}

int trace_udp_sendmsg_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct udp_pend_t *pp = udp_pending.lookup(&pid_tgid);
    if (pp == 0) return 0;
    struct udp_pend_t p = *pp;
    udp_pending.delete(&pid_tgid);
    if (ret < 0) return 0;

    u64 now = bpf_ktime_get_ns();
    struct udp_key_t k = {};
    k.sk = p.sk;
    COPY6(k.daddr, p.daddr);
    k.dport = p.dport;
    u64 window = (ntohs(p.dport) == 53) ? UDP_DNS_WINDOW_NS : UDP_WINDOW_NS;
    u64 *last = udp_seen.lookup(&k);
    if (last != 0 && now - *last < window) return 0;
    udp_seen.update(&k, &now);

    struct sock *sk = (struct sock *)p.sk;
    struct udp_event_t evt = {};
    evt.ts_us = p.t0_ns / 1000;      // gonderim BASLANGICI: ayni paketin yakalama zamanindan once
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid();
    if (p.family == 2) {
        bpf_probe_read_kernel(&evt.saddr[0], 4, &sk->__sk_common.skc_rcv_saddr);
    } else {
        bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    }
    COPY6(evt.daddr, p.daddr);
    bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport), &sk->__sk_common.skc_num);
    evt.dport = ntohs(p.dport);
    evt.family = p.family;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    udp_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
#endif

/* ---------------- Alan adi tahmini ---------------- */
int trace_getaddrinfo(struct pt_regs *ctx, const char __user *node) {
    if (node == NULL) return 0;
    struct host_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 1;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), node);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/* SSL_set_tlsext_host_name bir MAKRODUR: SSL_ctrl(s, 55, 0, name) olarak derlenir.
   Bu yuzden gercek sembol olan SSL_ctrl'e baglanip cmd/larg ile suzuyoruz. */
int trace_ssl_ctrl(struct pt_regs *ctx, void *ssl, int cmd, long larg, const char __user *parg) {
    if (cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME || larg != TLSEXT_NAMETYPE_host_name) return 0;
    if (parg == NULL) return 0;
    struct host_event_t evt = {};
    evt.ts_us = bpf_ktime_get_ns() / 1000;
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.source = 2;
    bpf_probe_read_user_str(&evt.host, sizeof(evt.host), parg);
    host_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""


# --------------------------------------------------------------- yardimcilar
def ip4_to_str(addr):
    # skc_*addr ag bayt sirasindadir; native endian ile bellek sirasi geri elde edilir.
    return socket.inet_ntop(socket.AF_INET, int(addr).to_bytes(4, byteorder=sys.byteorder))


def ip6_to_str(raw):
    try:
        try:
            buf = bytes(raw)          # u32[4] ctypes dizisi -> bellek sirasi = ag sirasi
        except Exception:
            buf = int(raw).to_bytes(16, byteorder="big", signed=False)
        if len(buf) != 16:
            buf = buf[:16].ljust(16, b"\x00")
        return socket.inet_ntop(socket.AF_INET6, buf)
    except Exception:
        return ""


def get_username(uid):
    if uid is None:
        return ""
    name = _UID_CACHE.get(uid)
    if name is not None:
        return name
    try:
        name = sanitize(pwd.getpwuid(uid).pw_name)
    except Exception:
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def _ip_obj(ip):
    obj = ipaddress.ip_address(ip)
    if obj.version == 6 and obj.ipv4_mapped is not None:
        obj = obj.ipv4_mapped      # ::ffff:127.0.0.1 gibi adresleri IPv4 gibi degerlendir
    return obj


def is_loopback(ip):
    try:
        return _ip_obj(ip).is_loopback
    except Exception:
        return False


def is_private(ip):
    try:
        obj = _ip_obj(ip)
        return obj.is_private or obj.is_link_local
    except Exception:
        return False


# ------------------------------------------------------------- surec zenginlestirme
_CTR_PATTERNS = (
    ("docker", re.compile(r"docker[-/]([0-9a-f]{12,64})")),
    ("containerd", re.compile(r"cri-containerd[-/]([0-9a-f]{12,64})")),
    ("crio", re.compile(r"crio[-/]([0-9a-f]{12,64})")),
    ("podman", re.compile(r"libpod[-/]([0-9a-f]{12,64})")),
    ("lxc", re.compile(r"/lxc(?:\.payload\.|/)([^/]+)")),
)
DOCKER_ROOT = "/var/lib/docker/containers"
_CTR_LABELS = {}


def parse_cgroup(text):
    """/proc/<pid>/cgroup icerigi -> (systemd unit, konteyner calisma zamani, konteyner kimligi)."""
    entries = []
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            entries.append(parts)
    chosen = None
    for parts in entries:                       # cgroup v2: "0::/yol"
        if parts[1] == "":
            chosen = parts[2]
            break
    if chosen is None:                          # cgroup v1: systemd hiyerarsisi
        for parts in entries:
            if "name=systemd" in parts[1].split(","):
                chosen = parts[2]
                break
    if chosen is None and entries:
        chosen = entries[0][2]
    path = chosen or ""
    runtime = cid = ""
    for rt, rx in _CTR_PATTERNS:
        m = rx.search(path)
        if m:
            runtime, cid = rt, m.group(1)
            break
    unit = ""
    if not runtime:
        for comp in reversed(path.split("/")):
            if comp.endswith((".service", ".scope")):
                unit = comp
                break
    return unit, runtime, cid


def container_label(runtime, cid):
    """'docker:ad' (docker icin config.v2.json'dan cozulursa) veya 'calisma_zamani:kisa_id'."""
    key = (runtime, cid)
    label = _CTR_LABELS.get(key)
    if label is not None:
        return label
    short = cid if runtime == "lxc" else cid[:12]
    label = f"{runtime}:{short}"
    if runtime == "docker":
        try:
            full = cid
            if len(cid) < 64:
                for d in os.listdir(DOCKER_ROOT):
                    if d.startswith(cid):
                        full = d
                        break
            with open(os.path.join(DOCKER_ROOT, full, "config.v2.json"), "r", encoding="utf-8") as f:
                name = str(json.load(f).get("Name", "")).lstrip("/")
            if name:
                label = f"docker:{name}"
        except Exception:
            pass
    _CTR_LABELS[key] = label
    return label


def read_proc_info(pid):
    """Surec bilgisi sozlugu; surec yoksa None (yalnizca zenginlestirme aciksa)."""
    info = {"ppid": None, "comm": "", "exe": "", "unit": "", "container": "", "cmdline": ""}
    base = f"/proc/{pid}"
    if ENRICH:
        try:
            with open(f"{base}/stat", "rb") as f:
                data = f.read().decode(errors="replace")
            lp, rp = data.find("("), data.rfind(")")
            info["comm"] = sanitize(data[lp + 1:rp])
            info["ppid"] = int(data[rp + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            return None
        try:
            info["exe"] = sanitize(os.readlink(f"{base}/exe"))
        except OSError:
            pass
        try:
            with open(f"{base}/cgroup", "r", encoding="utf-8", errors="replace") as f:
                unit, runtime, cid = parse_cgroup(f.read())
            info["unit"] = sanitize(unit)
            if runtime:
                info["container"] = sanitize(container_label(runtime, cid))
        except OSError:
            pass
    if not ARGS.no_cmd:
        try:
            with open(f"{base}/cmdline", "rb") as f:
                info["cmdline"] = sanitize(f.read(8192).replace(b"\x00", b" ").decode(errors="replace").strip())
        except OSError:
            pass
    return info


PROC_CACHE = {}          # pid -> (monotonic zaman, bilgi)
PROC_TTL = 10.0          # bu sureden taze ise yeniden okunmaz
PROC_KEEP = 300.0
PROC_MAX = 4096
_PROC_GC_LAST = 0.0


def _prune_proc_cache(now):
    global _PROC_GC_LAST
    if now - _PROC_GC_LAST < 5.0 and len(PROC_CACHE) <= PROC_MAX:
        return
    _PROC_GC_LAST = now
    for pid in [p for p, (t, _) in PROC_CACHE.items() if now - t > PROC_KEEP]:
        PROC_CACHE.pop(pid, None)
    if len(PROC_CACHE) > PROC_MAX:
        excess = len(PROC_CACHE) - PROC_MAX + 512
        for pid, _ in sorted(PROC_CACHE.items(), key=lambda kv: kv[1][0])[:excess]:
            PROC_CACHE.pop(pid, None)


def get_proc_info(pid):
    if not pid:
        return {}
    now = time.monotonic()
    ent = PROC_CACHE.get(pid)
    if ent is not None and now - ent[0] < PROC_TTL:
        return ent[1]
    info = read_proc_info(pid)
    if info is None:                      # surec cikmis olabilir: eski bilgi daha iyidir
        return ent[1] if ent is not None else {}
    PROC_CACHE[pid] = (now, info)
    _prune_proc_cache(now)
    return info


# ------------------------------------------------------------- alan adi tahmini
# Bu bolumde zaman damgalari DUVAR SAATI saniyesidir (olay zamani).
DNS_MAP_TTL = 300.0
DNS_MAP_MAX = 50000
HOST_BY_IP = OrderedDict()        # ip metni -> (ad, zaman)
HOST_BY_PID_IP = OrderedDict()    # (pid, ip metni) -> (ad, zaman)


def cleanup_host_cache():
    """Her olayda degil, en fazla saniyede bir calisir (O(n) tarama maliyeti icin)."""
    global _HOST_GC_LAST
    now = time.time()
    if now - _HOST_GC_LAST < 1.0:
        return
    _HOST_GC_LAST = now
    for pid in [p for p, v in HOST_CACHE.items() if now - v["ts"] > HOST_TTL * 3]:
        HOST_CACHE.pop(pid, None)
    if len(HOST_CACHE) > 10000:      # ani PID patlamasina karsi sert limit
        for pid, _ in sorted(HOST_CACHE.items(), key=lambda kv: kv[1]["ts"])[:2000]:
            HOST_CACHE.pop(pid, None)
    for od in (HOST_BY_IP, HOST_BY_PID_IP):
        while od and (len(od) > DNS_MAP_MAX or now - next(iter(od.values()))[1] > DNS_MAP_TTL):
            od.popitem(last=False)


def remember_host(pid, host, source, ts_s):
    if not ENABLE_HOST_ENRICHMENT:
        return
    host = (host or "").strip()
    # Yalnizca makul alan adi/IP karakterleri: bosluk, satir sonu, kacis dizisi vb. reddedilir.
    if not _HOST_RE.fullmatch(host):
        return
    HOST_CACHE[pid] = {"host": host, "source": source, "ts": ts_s}


def remember_dns_answer(pid, ip, name, ts_s):
    """DNS yanitindaki bir A/AAAA adresini, sorulan adla eslestirir."""
    if not ENABLE_HOST_ENRICHMENT or not _HOST_RE.fullmatch(name or ""):
        return
    HOST_BY_IP[ip] = (name, ts_s)
    HOST_BY_IP.move_to_end(ip)
    if pid:
        HOST_BY_PID_IP[(pid, ip)] = (name, ts_s)
        HOST_BY_PID_IP.move_to_end((pid, ip))


def resolve_host(pid, rip, now_s):
    """Uzak IP icin (ad, kaynak). Oncelik: sni > dns-resp > dns > dns-ip. Hepsi TAHMINDIR."""
    if not ENABLE_HOST_ENRICHMENT:
        return None, None
    cleanup_host_cache()
    item = HOST_CACHE.get(pid)
    fresh = item is not None and now_s - item["ts"] <= HOST_TTL
    if fresh and item["source"] == "sni":
        return item["host"], "sni"
    e = HOST_BY_PID_IP.get((pid, rip))
    if e is not None and now_s - e[1] <= DNS_MAP_TTL:
        return e[0], "dns-resp"
    if fresh:
        return item["host"], item["source"]
    e = HOST_BY_IP.get(rip)
    if e is not None and now_s - e[1] <= DNS_MAP_TTL:
        return e[0], "dns-ip"
    return None, None


# ------------------------------------------------------------- karar: kaydet / atla / bastir
def is_unspecified(ip):
    try:
        return ipaddress.ip_address(ip).is_unspecified
    except Exception:
        return False


def should_skip(direction, rec):
    if IGNORE_ROOT and rec["uid"] == 0:
        return True
    if rec.get("event") == "dns":
        return False      # DNS kayitlari loopback/ozel-IP suzgeclerinden etkilenmez (cozucu genelde yerel/ozeldir)
    if (IGNORE_LOOPBACK and is_loopback(rec["remote_ip"])
            and (is_loopback(rec["local_ip"]) or is_unspecified(rec["local_ip"]))):
        return True
    if direction == "outbound" and IGNORE_PRIVATE_OUT and is_private(rec["remote_ip"]):
        return True
    if direction == "inbound" and IGNORE_PRIVATE_IN and is_private(rec["remote_ip"]):
        return True
    return False


def service_port(direction, rec):
    return rec["remote_port"] if direction == "outbound" else rec["local_port"]


DEDUPE = {}
DEDUPE_MAX = 20000


def _emit_repeat(direction, ent):
    if ent["count"] <= 0:
        return
    r = dict(ent["rec"])
    r.update(event="repeat", ts=ent["last_ts"], count=ent["count"], window_s=ARGS.dedupe)
    emit(direction, r)


def dedupe_hit(direction, rec, now_s):
    """True: bu acilis penceredeki bir tekrardir, bastirilmali."""
    win = ARGS.dedupe
    if win <= 0:
        return False
    key = (direction, rec["pid"], rec["comm"], rec.get("proto"), rec["remote_ip"],
           service_port(direction, rec), rec.get("dns_name", ""), rec.get("dns_type", ""))
    ent = DEDUPE.get(key)
    if ent is not None:
        if now_s - ent["first"] < win:
            ent["count"] += 1
            ent["last_ts"] = rec["ts"]
            return True
        _emit_repeat(direction, ent)
    if len(DEDUPE) >= DEDUPE_MAX:
        flush_dedupe(now_s)
    DEDUPE[key] = {"first": now_s, "count": 0, "last_ts": rec["ts"], "rec": rec, "direction": direction}
    return False


def flush_dedupe(now_s=None, force=False):
    now_s = time.time() if now_s is None else now_s
    for key in list(DEDUPE):
        ent = DEDUPE[key]
        if force or now_s - ent["first"] >= ARGS.dedupe:
            _emit_repeat(ent["direction"], ent)
            del DEDUPE[key]


def decide(direction, rec, now_s, use_dedupe):
    """'log' | 'drop' | 'suppress'"""
    if should_skip(direction, rec):
        return "drop"
    if rules_action(direction, rec) == "ignore":
        return "drop"
    if use_dedupe and dedupe_hit(direction, rec, now_s):
        return "suppress"
    return "log"


# sk -> (karar, host_guess, kaynak, surec bilgisi): close kaydi acilisla ayni karari izler
TRACK = OrderedDict()
TRACK_MAX = 100000


def track_put(sk, decision, host, src, info):
    if not sk:
        return
    TRACK[sk] = (decision, host, src, info)
    TRACK.move_to_end(sk)
    while len(TRACK) > TRACK_MAX:
        TRACK.popitem(last=False)


# ------------------------------------------------------------- canli cikti
LIVE = not ARGS.quiet
COLOR = sys.stdout.isatty() and not ARGS.no_color
C_OUT, C_IN, C_DIM, C_RESET, C_RED, C_DNS = (
    ("\033[36m", "\033[33m", "\033[2m", "\033[0m", "\033[31m", "\033[35m") if COLOR
    else ("", "", "", "", "", ""))

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
    print(f'{C_DIM}  v{VERSION} | monitor-only | giden + gelen TCP | format={ARGS.format} | Ctrl+C ile durdur{C_RESET}\n',
          flush=True)


def live_print(direction, rec):
    if not LIVE:
        return
    evt = rec.get("event", "open")
    if evt == "snapshot":
        return
    t = datetime.now().strftime("%H:%M:%S")
    who = _who(rec)
    path = _path_str(direction, rec)
    out_dir = direction == "outbound"
    color = C_OUT if out_dir else C_IN
    udp = rec.get("proto") == "udp"
    dlabel = ("OUT" if out_dir else "IN ") if not udp else ("UDP" if out_dir else "UDP<")
    host = ""
    if out_dir and rec.get("host_guess"):
        host = f' ({rec["host_guess"]}, {rec["host_guess_source"]})'
    if evt == "dns":
        ans = ",".join(rec.get("dns_answers") or [])
        bad = rec.get("dns_rcode") != "NOERROR"
        line = (f'{C_DIM}{t}{C_RESET} {C_DNS}{"DNS" if out_dir else "DNS<"}{C_RESET} {who}  '
                f'{rec.get("dns_type")} {rec.get("dns_name")}')
        if ans:
            line += f' => {ans}'
        line += f'  {C_RED if bad else ""}{rec.get("dns_rcode")}{C_RESET}'
        if rec.get("dns_ms") is not None:
            line += f' {human_dur(rec["dns_ms"])}'
        line += f'  {C_DIM}via {rec["remote_ip"] if out_dir else rec["local_ip"]}{C_RESET}'
    elif evt == "open":
        line = f'{C_DIM}{t}{C_RESET} {color}{dlabel}{C_RESET} {who}  {path}{host}'
    elif evt == "close":
        bad = rec.get("outcome") == "failed"
        out_col = C_RED if bad else ""
        line = (f'{C_DIM}{t} {dlabel.strip()}-CLOSE{C_RESET} {who}  {path}{host}  '
                f'dur={human_dur(rec.get("duration_ms"))} tx={human_bytes(rec.get("bytes_tx"))} '
                f'rx={human_bytes(rec.get("bytes_rx"))} {out_col}outcome={rec.get("outcome")}{C_RESET}')
    else:
        line = f'{C_DIM}{t} {dlabel.strip()}-REPEAT{C_RESET} {who}  {path}  repeated={rec.get("count")}'
        if rec.get("dns_name"):
            line += f' {rec.get("dns_type")} {rec.get("dns_name")}'
    if ARGS.show_cmd and not ARGS.no_cmd and rec.get("cmdline"):
        line += f'  {C_DIM}| {rec["cmdline"][:120]}{C_RESET}'
    print(line, flush=True)


def emit(direction, rec):
    store(direction, rec)
    live_print(direction, rec)


# ------------------------------------------------------------- olay hatti
# Tum olaylar (BPF + DNS paketleri) OLAY ZAMANINA gore siralanip LAG_S sonra islenir; boylece
# farkli perf tamponlari ile paket soketi arasindaki gecikme farklari sirayi bozmaz.
LAG_S = 0.3
POLL_MS = 100
PENDING = []              # heap: (duvar saati, sira no, tur, yuk)
_SEQ = 0

FLOW_TTL = 120.0
FLOWS = OrderedDict()     # (istemci portu, cozucu ham adresi) -> (zaman, pid, uid, comm)
FLOWS_MAX = 20000


def event_wall(ts_us):
    """BPF (CLOCK_MONOTONIC) zamanini duvar saatine cevirir."""
    return time.time() - (time.monotonic() - ts_us / 1e6)


def enqueue_wall(kind, wall, payload):
    global _SEQ
    _SEQ += 1
    heapq.heappush(PENDING, (wall, _SEQ, kind, payload))


def enqueue(kind, ts_us, payload):
    """Geri cagirimlar yalnizca kuyruga ekler; isleme poll'den sonra, olay zamanina gore yapilir."""
    enqueue_wall(kind, event_wall(ts_us), payload)


def build_rec(event, wall, direction, family, lip, lport, rip, rport, pid, uid, comm, info, proto="tcp"):
    return {
        "ts": datetime.fromtimestamp(wall, timezone.utc).isoformat(),
        "hostname": HOSTNAME,
        "event": event,
        "proto": proto,
        "uid": uid,
        "user": get_username(uid),
        "pid": pid,
        "ppid": info.get("ppid"),
        "comm": comm,
        "exe": info.get("exe", ""),
        "unit": info.get("unit", ""),
        "container": info.get("container", ""),
        "cmdline": info.get("cmdline", ""),
        "family": family,
        "local_ip": lip,
        "local_port": lport,
        "remote_ip": rip,
        "remote_port": rport,
    }


def _comm_str(raw):
    if isinstance(raw, str):
        return sanitize(raw)
    return sanitize(bytes(raw).split(b"\x00", 1)[0].decode(errors="replace"))


def remember_flow(sport, raddr, wall, pid, uid, comm):
    key = (sport, raddr)
    FLOWS[key] = (wall, pid, uid, comm)
    FLOWS.move_to_end(key)
    while len(FLOWS) > FLOWS_MAX:
        FLOWS.popitem(last=False)


# ------------------------------------------------------------- DNS ayristirma
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
              33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA",
              64: "SVCB", 65: "HTTPS", 99: "SPF", 255: "ANY", 257: "CAA"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def _dns_label(raw):
    """Etiket baytlari -> guvenli ASCII (nokta, ters bolu ve yazdirilamayanlar \\DDD ile kacirilir)."""
    out = []
    for c in raw:
        if c in (0x2E, 0x5C):
            out.append("\\" + chr(c))
        elif 0x21 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append("\\%03d" % c)
    return "".join(out)


def _dns_name(buf, off):
    """Sikistirma isaretcilerini de cozer. Gecersiz/dongulu/asiri uzunsa ValueError."""
    labels, end, hops, total, n = [], None, 0, 0, len(buf)
    while True:
        if off >= n:
            raise ValueError("kisa paket")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= n:
                raise ValueError("kisa isaretci")
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 16 or ptr >= n:
                raise ValueError("isaretci dongusu")
            off = ptr
            continue
        if ln & 0xC0:
            raise ValueError("gecersiz etiket")
        off += 1
        if off + ln > n:
            raise ValueError("kisa etiket")
        total += ln + 1
        if total > 255:
            raise ValueError("ad cok uzun")
        labels.append(_dns_label(buf[off:off + ln]))
        off += ln
    if end is None:
        end = off
    return (".".join(labels).lower() or "."), end


def parse_dns(buf):
    """DNS mesaji -> sozluk (id, qr, rcode, tc, qname, qtype, answers[(tur, deger)]) ya da None."""
    if len(buf) < 12:
        return None
    tid, flags, qd, an = struct.unpack("!HHHH", buf[:8])
    if (flags >> 11) & 0xF != 0 or qd < 1 or qd > 8:      # yalnizca standart sorgu/yanit
        return None
    qr = (flags >> 15) & 1
    try:
        qname, off = _dns_name(buf, 12)
        if off + 4 > len(buf):
            return None
        qtype = struct.unpack("!H", buf[off:off + 2])[0]
        off += 4
        for _ in range(qd - 1):                    # ek sorulari atla
            _n, off = _dns_name(buf, off)
            off += 4
    except ValueError:
        return None
    answers = []
    if qr:
        try:
            for _ in range(min(an, 64)):
                _n, off = _dns_name(buf, off)
                if off + 10 > len(buf):
                    break
                rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
                off += 10
                if off + rdlen > len(buf):
                    break
                if rtype == 1 and rdlen == 4:
                    answers.append(("A", socket.inet_ntop(socket.AF_INET, buf[off:off + 4])))
                elif rtype == 28 and rdlen == 16:
                    answers.append(("AAAA", socket.inet_ntop(socket.AF_INET6, buf[off:off + 16])))
                elif rtype == 5:
                    try:
                        answers.append(("CNAME", _dns_name(buf, off)[0]))
                    except ValueError:
                        pass
                off += rdlen
        except ValueError:
            pass                                   # eldekini koru
    return {"id": tid, "qr": qr, "rcode": flags & 0xF, "tc": bool((flags >> 9) & 1),
            "qname": qname, "qtype": qtype, "answers": answers}


# ------------------------------------------------------------- yerel adresler / IP-UDP ayristirma
LOCAL_ADDRS = set()       # ham baytlar (4 veya 16)
_LOCAL_AT = 0.0


def refresh_local_addrs(force=False):
    """Bu makinenin (ana ag ad alani) adreslerini /proc/net/fib_trie ve if_inet6'dan okur; 30 sn'de bir."""
    global _LOCAL_AT, LOCAL_ADDRS
    now = time.monotonic()
    if not force and now - _LOCAL_AT < 30.0:
        return
    _LOCAL_AT = now
    s = set()
    try:
        last = None
        with open("/proc/net/fib_trie", "r", encoding="ascii", errors="replace") as f:
            for ln in f:
                t = ln.strip()
                if t.startswith("|--"):
                    last = t[3:].strip()
                elif t.startswith("/32 host LOCAL") and last:
                    try:
                        s.add(socket.inet_aton(last))
                    except OSError:
                        pass
    except OSError:
        pass
    try:
        with open("/proc/net/if_inet6", "r", encoding="ascii", errors="replace") as f:
            for ln in f:
                parts = ln.split()
                if parts and len(parts[0]) == 32:
                    try:
                        s.add(bytes.fromhex(parts[0]))
                    except ValueError:
                        pass
    except OSError:
        pass
    LOCAL_ADDRS = s


def is_local(raw):
    if raw in LOCAL_ADDRS:
        return True
    if len(raw) == 4:
        return raw[0] == 127
    return raw == b"\x00" * 15 + b"\x01"


def ip_text(raw):
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


def _norm_addr(raw):
    if len(raw) == 16 and raw[:12] == b"\x00" * 10 + b"\xff\xff":
        return raw[12:]
    return raw


def parse_ip_udp(pkt):
    """Ag katmani paketi (IPv4/IPv6) -> UDP ozeti ya da None. Parcalarin yalniz ilkini kabul eder."""
    n = len(pkt)
    if n < 20:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if ihl < 20 or n < ihl + 8 or pkt[9] != 17:
            return None
        if struct.unpack("!H", pkt[6:8])[0] & 0x1FFF:
            return None
        src, dst, off = pkt[12:16], pkt[16:20], ihl
    elif ver == 6:
        if n < 48 or pkt[6] != 17:
            return None
        src, dst, off = _norm_addr(pkt[8:24]), _norm_addr(pkt[24:40]), 40
    else:
        return None
    sport, dport, ulen = struct.unpack("!HHH", pkt[off:off + 6])
    if ulen < 8:
        return None
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "payload": pkt[off + 8:off + ulen]}


# ------------------------------------------------------------- DNS paket yakalama (AF_PACKET + klasik BPF)
SO_ATTACH_FILTER = 26
SO_RCVBUFFORCE = 33
SO_TIMESTAMPNS_OPT = getattr(socket, "SO_TIMESTAMPNS", 35)
PKT_SOCK = None
_PKT_ERR_WARNED = False


class SockFilter(ct.Structure):
    _fields_ = [("code", ct.c_ushort), ("jt", ct.c_ubyte), ("jf", ct.c_ubyte), ("k", ct.c_uint)]


class SockFprog(ct.Structure):
    _fields_ = [("len", ct.c_ushort), ("filter", ct.POINTER(SockFilter))]


_LDB_ABS, _LDH_ABS, _LDH_IND, _LDXB_MSH = 0x30, 0x28, 0x48, 0xB1
_AND_K, _JEQ_K, _JSET_K, _RET_K = 0x54, 0x15, 0x45, 0x06


def dns_bpf_program():
    """Klasik BPF: IPv4/IPv6 UDP, kaynak veya hedef port 53 (parcalanmis paketlerin ilki dahil). Paket ag
    katmanindan baslar (SOCK_DGRAM). Etiketler (str) atlama hedefidir."""
    prog = [
        (_LDB_ABS, 0, 0, 0),
        (_AND_K, 0, 0, 0xF0),
        (_JEQ_K, "v4", "chk6", 0x40),
        "v4",
        (_LDB_ABS, 0, 0, 9),
        (_JEQ_K, "v4a", "rej", 17),
        "v4a",
        (_LDH_ABS, 0, 0, 6),
        (_JSET_K, "rej", "v4b", 0x1FFF),
        "v4b",
        (_LDXB_MSH, 0, 0, 0),
        (_LDH_IND, 0, 0, 0),
        (_JEQ_K, "acc", "v4c", 53),
        "v4c",
        (_LDH_IND, 0, 0, 2),
        (_JEQ_K, "acc", "rej", 53),
        "chk6",
        (_JEQ_K, "v6", "rej", 0x60),
        "v6",
        (_LDB_ABS, 0, 0, 6),
        (_JEQ_K, "v6a", "rej", 17),
        "v6a",
        (_LDH_ABS, 0, 0, 40),
        (_JEQ_K, "acc", "v6b", 53),
        "v6b",
        (_LDH_ABS, 0, 0, 42),
        (_JEQ_K, "acc", "rej", 53),
        "acc",
        (_RET_K, 0, 0, 0x40000),
        "rej",
        (_RET_K, 0, 0, 0),
    ]
    labels, insns = {}, []
    for item in prog:
        if isinstance(item, str):
            labels[item] = len(insns)
        else:
            insns.append(item)
    out = []
    for i, (op, jt, jf, k) in enumerate(insns):
        jt = labels[jt] - i - 1 if isinstance(jt, str) else jt
        jf = labels[jf] - i - 1 if isinstance(jf, str) else jf
        out.append((op, jt, jf, k))
    return out


def open_dns_socket():
    """Tum arayuzlerde 53/udp paketlerini alan, bloklamayan AF_PACKET soketi (root gerekir)."""
    # Not: bind(("", proto)) Python 3.13'te ENODEV verir; bu yuzden bind yok. ETH_P_ALL ile olusturulan
    # baglanmamis AF_PACKET soketi tum arayuzlerden alir. Suzgec takilana kadar gelebilecek birkac
    # fazla paketi drain_packets/parse_ip_udp zaten eler.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    try:
        insns = dns_bpf_program()
        arr = (SockFilter * len(insns))(*[SockFilter(*i) for i in insns])
        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(SockFprog(len(insns), arr)))
        for opt in (SO_RCVBUFFORCE, socket.SO_RCVBUF):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, 4 * 1024 * 1024)
                break
            except OSError:
                continue
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_OPT, 1)
        except OSError:
            pass
        s.setblocking(False)
    except Exception:
        s.close()
        raise
    return s


def drain_packets(limit=4000):
    global _PKT_ERR_WARNED
    if PKT_SOCK is None:
        return
    for _ in range(limit):
        try:
            data, anc, _flags, addr = PKT_SOCK.recvmsg(8192, socket.CMSG_SPACE(16))
        except (BlockingIOError, InterruptedError):
            break
        except OSError as e:
            if not _PKT_ERR_WARNED:
                _PKT_ERR_WARNED = True
                warn(f"DNS paket soketi okuma hatasi: {e}")
            break
        pkttype = addr[2] if isinstance(addr, tuple) and len(addr) > 2 else 0
        if pkttype not in (0, 4):             # yalnizca bize gelen (HOST) ve bizden giden (OUTGOING)
            continue
        wall = None
        for level, ctype, cdata in anc:
            if level == socket.SOL_SOCKET and ctype == SO_TIMESTAMPNS_OPT:
                if len(cdata) >= 16:
                    sec, nsec = struct.unpack("@qq", cdata[:16])
                elif len(cdata) >= 8:
                    sec, nsec = struct.unpack("@ii", cdata[:8])
                else:
                    continue
                wall = sec + nsec / 1e9
        if wall is None:
            wall = time.time()
        parsed = parse_ip_udp(data)
        if parsed is not None and (parsed["sport"] == 53 or parsed["dport"] == 53):
            enqueue_wall("pkt", wall, parsed)


# ------------------------------------------------------------- DNS islemleri
DNS_TIMEOUT = 5.0
DNS_PENDING = OrderedDict()       # (istemci, istemci portu, sunucu, id) -> sorgu
DNS_PENDING_MAX = 20000
DNS_SEEN = OrderedDict()          # ayni paketin birden cok arayuzde gorunmesine karsi


def _new_txn(wall, client, cport, server, msg):
    local_c, local_s = is_local(client), is_local(server)
    if not (local_c or local_s):
        return None                   # bu makinenin ucu olmayan (yonlendirilen) trafik
    direction = "outbound" if local_c else "inbound"
    flow = None
    if direction == "outbound":
        flow = FLOWS.get((cport, server))
        if flow is not None and abs(wall - flow[0]) > FLOW_TTL:
            flow = None
    return {"wall": wall, "client": client, "cport": cport, "server": server, "direction": direction,
            "flow": flow, "qname": msg["qname"], "qtype": msg["qtype"]}


def emit_dns(txn, rcode_str, answers, tc, ms):
    flow = txn["flow"]
    pid, uid, comm = (flow[1], flow[2], flow[3]) if flow else (0, None, "-")
    direction = txn["direction"]
    family = "ipv4" if len(txn["server"]) == 4 else "ipv6"
    cip, sip = ip_text(txn["client"]), ip_text(txn["server"])
    if direction == "outbound":
        lip, lport, rip, rport = cip, txn["cport"], sip, 53
    else:
        lip, lport, rip, rport = sip, 53, cip, txn["cport"]
    info = get_proc_info(pid) if pid else {}
    rec = build_rec("dns", txn["wall"], direction, family, lip, lport, rip, rport,
                    pid, uid, comm, info, proto="udp")
    rec["dns_name"] = txn["qname"]
    rec["dns_type"] = DNS_QTYPES.get(txn["qtype"], f"TYPE{txn['qtype']}")
    rec["dns_rcode"] = rcode_str
    rec["dns_answers"] = [(v if t in ("A", "AAAA") else f"CNAME:{v}") for t, v in answers[:16]]
    rec["dns_ms"] = None if ms is None else round(ms, 3)
    rec["dns_tc"] = bool(tc)
    for t, v in answers:
        if t in ("A", "AAAA"):
            remember_dns_answer(pid if direction == "outbound" else 0, v, txn["qname"], txn["wall"])
    if decide(direction, rec, txn["wall"], True) == "log":
        emit(direction, rec)


def dns_expire(cutoff):
    while DNS_PENDING:
        _key, txn = next(iter(DNS_PENDING.items()))
        if txn["wall"] + DNS_TIMEOUT > cutoff:
            break
        DNS_PENDING.popitem(last=False)
        emit_dns(txn, "timeout", [], False, None)


def do_pkt(wall, p):
    msg = parse_dns(p["payload"])
    if msg is None:
        return
    src, dst, sport, dport = p["src"], p["dst"], p["sport"], p["dport"]
    if msg["qr"]:
        if sport != 53:
            return
        client, cport, server = dst, dport, src
    else:
        if dport != 53:
            return
        client, cport, server = src, sport, dst
    dkey = (src, sport, dst, dport, msg["id"], msg["qr"], hash(p["payload"]))
    seen = DNS_SEEN.get(dkey)
    if seen is not None and abs(wall - seen) < 1.5:
        return
    DNS_SEEN[dkey] = wall
    DNS_SEEN.move_to_end(dkey)
    while DNS_SEEN and (len(DNS_SEEN) > 20000 or wall - next(iter(DNS_SEEN.values())) > 5.0):
        DNS_SEEN.popitem(last=False)
    txkey = (client, cport, server, msg["id"])
    if not msg["qr"]:
        txn = _new_txn(wall, client, cport, server, msg)
        if txn is None:
            return
        DNS_PENDING[txkey] = txn
        DNS_PENDING.move_to_end(txkey)
        while len(DNS_PENDING) > DNS_PENDING_MAX:
            DNS_PENDING.popitem(last=False)
        return
    txn = DNS_PENDING.get(txkey)
    ms = None
    if txn is not None and txn["qname"] == msg["qname"] and txn["qtype"] == msg["qtype"]:
        DNS_PENDING.pop(txkey, None)
        ms = max(0.0, (wall - txn["wall"]) * 1000.0)
    else:
        txn = _new_txn(wall, client, cport, server, msg)     # sorgu kacmis (yakalama oncesi)
        if txn is None:
            return
    emit_dns(txn, DNS_RCODES.get(msg["rcode"], f"RCODE{msg['rcode']}"), msg["answers"], msg["tc"], ms)


# ------------------------------------------------------------- olay isleyicileri
def do_host(wall, p):
    remember_host(p["pid"], p["host"], p["source"], wall)


def do_open(wall, p):
    direction, family = p["direction"], p["family"]
    if family == "ipv4":
        lip, rip = ip4_to_str(p["saddr"]), ip4_to_str(p["daddr"])
    else:
        lip, rip = ip6_to_str(p["saddr"]), ip6_to_str(p["daddr"])
    pid = p["pid"]
    info = get_proc_info(pid)
    rec = build_rec("open", wall, direction, family, lip, p["sport"], rip, p["dport"],
                    pid, p["uid"], _comm_str(p["comm"]), info)
    host = src = None
    if direction == "outbound":
        host, src = resolve_host(pid, rip, wall)
        if host:
            rec["host_guess"] = host
            rec["host_guess_source"] = src
    decision = decide(direction, rec, wall, True)
    if LIFECYCLE_ON:
        track_put(p["sk"], decision, host, src, info)
    if decision == "log":
        emit(direction, rec)


def do_close(wall, p):
    direction = "outbound" if p["dir"] == 1 else "inbound"
    if p["family"] == 2:
        family = "ipv4"
        lip = socket.inet_ntop(socket.AF_INET, p["saddr"][:4])
        rip = socket.inet_ntop(socket.AF_INET, p["daddr"][:4])
    else:
        family = "ipv6"
        lip, rip = ip6_to_str(p["saddr"]), ip6_to_str(p["daddr"])
    ent = TRACK.pop(p["sk"], None)
    info = ent[3] if ent is not None else {}
    rec = build_rec("close", wall, direction, family, lip, p["sport"], rip, p["dport"],
                    p["pid"], p["uid"], _comm_str(p["comm"]), info)
    if ent is not None:
        decision, host, src = ent[0], ent[1], ent[2]
        if host:
            rec["host_guess"] = host
            rec["host_guess_source"] = src
    else:
        decision = decide(direction, rec, wall, False)
    if decision != "log":
        return
    rec["duration_ms"] = round(p["dur_us"] / 1000.0, 3)
    rec["bytes_tx"] = p["tx"] if BYTES_ON else None
    rec["bytes_rx"] = p["rx"] if BYTES_ON else None
    rec["outcome"] = "ok" if p["established"] else "failed"
    emit(direction, rec)


def do_udp(wall, p):
    if p["family"] == 2:
        af, family, n = socket.AF_INET, "ipv4", 4
    else:
        af, family, n = socket.AF_INET6, "ipv6", 16
    lraw, rraw = p["saddr"][:n], p["daddr"][:n]
    lip, rip = socket.inet_ntop(af, lraw), socket.inet_ntop(af, rraw)
    pid, uid = p["pid"], p["uid"]
    comm = _comm_str(p["comm"])
    if p["dport"] == 53:
        remember_flow(p["sport"], rraw, wall, pid, uid, comm)      # DNS paketlerinin surec eslemesi
        if DNS_ON:
            return                                                  # kayit paket yakalamadan gelir
    info = get_proc_info(pid)
    rec = build_rec("open", wall, "outbound", family, lip, p["sport"], rip, p["dport"],
                    pid, uid, comm, info, proto="udp")
    host, src = resolve_host(pid, rip, wall)
    if host:
        rec["host_guess"] = host
        rec["host_guess_source"] = src
    if decide("outbound", rec, wall, True) == "log":
        emit("outbound", rec)


HANDLERS = {"host": do_host, "open": do_open, "close": do_close, "udp": do_udp, "pkt": do_pkt}


def process_pending(force=False):
    """LAG_S'den eski olaylari zaman sirasiyla isler. force: hepsini (kapanista)."""
    cutoff = time.time() - LAG_S
    while PENDING and (force or PENDING[0][0] <= cutoff):
        wall, _seq, kind, payload = heapq.heappop(PENDING)
        try:
            HANDLERS[kind](wall, payload)
        except Exception as e:
            print(f"isleme hatasi ({kind}): {e}", file=sys.stderr, flush=True)
    if not force:
        try:
            dns_expire(cutoff)
        except Exception as e:
            print(f"isleme hatasi (dns_expire): {e}", file=sys.stderr, flush=True)


def make_open_cb(perf_name, direction, family):
    def cb(cpu, data, size):
        try:
            ev = b[perf_name].event(data)
            if family == "ipv4":
                sa, da = int(ev.saddr), int(ev.daddr)
            else:
                sa, da = bytes(ev.saddr), bytes(ev.daddr)
            enqueue("open", int(ev.ts_us), {
                "direction": direction, "family": family, "sk": int(ev.sk),
                "pid": int(ev.pid), "uid": int(ev.uid), "saddr": sa, "daddr": da,
                "sport": int(ev.sport), "dport": int(ev.dport), "comm": bytes(ev.comm),
            })
        except Exception as e:
            print(f"handler hatasi ({perf_name}): {e}", file=sys.stderr, flush=True)
    return cb


def close_cb(cpu, data, size):
    try:
        ev = b["close_events"].event(data)
        enqueue("close", int(ev.ts_us), {
            "sk": int(ev.sk), "dur_us": int(ev.dur_us), "tx": int(ev.tx_bytes), "rx": int(ev.rx_bytes),
            "pid": int(ev.pid), "uid": int(ev.uid),
            "saddr": bytes(ev.saddr), "daddr": bytes(ev.daddr),
            "sport": int(ev.sport), "dport": int(ev.dport), "family": int(ev.family),
            "dir": int(ev.dir), "established": int(ev.established), "comm": bytes(ev.comm),
        })
    except Exception as e:
        print(f"handler hatasi (close_events): {e}", file=sys.stderr, flush=True)


def udp_cb(cpu, data, size):
    try:
        ev = b["udp_events"].event(data)
        enqueue("udp", int(ev.ts_us), {
            "pid": int(ev.pid), "uid": int(ev.uid),
            "saddr": bytes(ev.saddr), "daddr": bytes(ev.daddr),
            "sport": int(ev.sport), "dport": int(ev.dport), "family": int(ev.family),
            "comm": bytes(ev.comm),
        })
    except Exception as e:
        print(f"handler hatasi (udp_events): {e}", file=sys.stderr, flush=True)


def host_cb(cpu, data, size):
    try:
        ev = b["host_events"].event(data)
        host = bytes(ev.host).split(b"\x00", 1)[0].decode(errors="replace")
        enqueue("host", int(ev.ts_us), {
            "pid": int(ev.pid), "source": "dns" if int(ev.source) == 1 else "sni", "host": host,
        })
    except Exception as e:
        print(f"handler hatasi (host_events): {e}", file=sys.stderr, flush=True)


# ------------------------------------------------------------- baslangic anlik goruntusu
def hex_addr(h, v6):
    """/proc/net/tcp* adres alani -> metin (alanlar ana makine bayt sirasinda yazilir)."""
    if not v6:
        return ip4_to_str(int(h, 16))
    words = [int(h[i:i + 8], 16).to_bytes(4, byteorder=sys.byteorder) for i in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(words))


def parse_proc_net_tcp(path, v6):
    rows = []
    try:
        with open(path, "r", encoding="ascii", errors="replace") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return rows
    for ln in lines:
        f = ln.split()
        if len(f) < 10:
            continue
        try:
            la, lp = f[1].split(":")
            ra, rp = f[2].split(":")
            rows.append({"lip": hex_addr(la, v6), "lport": int(lp, 16),
                         "rip": hex_addr(ra, v6), "rport": int(rp, 16),
                         "state": f[3], "uid": int(f[7]), "inode": int(f[9]), "v6": v6})
        except (ValueError, OSError):
            continue
    return rows


def normalize_ip(ip, v6):
    if v6:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.ipv4_mapped is not None:
                return str(obj.ipv4_mapped), "ipv4"
        except ValueError:
            pass
        return ip, "ipv6"
    return ip, "ipv4"


def build_inode_pid_map(wanted):
    """Soket inode'u -> surec (tgid). Yalnizca `wanted` icindekiler aranir."""
    found = {}
    if not wanted:
        return found
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        fd_dir = f"/proc/{name}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                try:
                    ino = int(target[8:-1])
                except ValueError:
                    continue
                if ino in wanted and ino not in found:
                    found[ino] = int(name)
        if len(found) == len(wanted):
            break
    return found


def take_snapshot():
    """Baslangicta ESTABLISHED olan baglantilari 'snapshot' olarak kaydeder. Doner: (kaydedilen, atlanan)."""
    rows = parse_proc_net_tcp("/proc/net/tcp", False) + parse_proc_net_tcp("/proc/net/tcp6", True)
    listen_ports = {r["lport"] for r in rows if r["state"] == "0A"}
    estab = [r for r in rows if r["state"] == "01"]
    inode_pid = build_inode_pid_map({r["inode"] for r in estab})
    now_wall = time.time()
    logged = skipped = 0
    for r in estab:
        direction = "inbound" if r["lport"] in listen_ports else "outbound"
        pid = inode_pid.get(r["inode"], 0)
        info = get_proc_info(pid)
        comm = sanitize(info.get("comm") or "?")
        lip, _ = normalize_ip(r["lip"], r["v6"])
        rip, family = normalize_ip(r["rip"], r["v6"])
        rec = build_rec("snapshot", now_wall, direction, family, lip, r["lport"], rip, r["rport"],
                        pid, r["uid"], comm, info)
        if decide(direction, rec, 0.0, False) != "log":
            skipped += 1
            continue
        store(direction, rec)
        logged += 1
    return logged, skipped


# ------------------------------------------------------------- olay kaybi takibi
LOST = {}
_LOST_REPORTED_TOTAL = 0
_LOST_REPORTED_AT = 0.0


def make_lost_cb(name):
    def cb(lost):
        LOST[name] = LOST.get(name, 0) + int(lost)
    return cb


def report_lost(force=False):
    """Kayip olay sayisi artmissa (en fazla 5 sn'de bir) stderr'e uyari yazar."""
    global _LOST_REPORTED_TOTAL, _LOST_REPORTED_AT
    total = sum(LOST.values())
    if total <= _LOST_REPORTED_TOTAL:
        return
    now = time.time()
    if not force and now - _LOST_REPORTED_AT < 5.0:
        return
    _LOST_REPORTED_AT = now
    _LOST_REPORTED_TOTAL = total
    detail = ", ".join(f"{k}={v}" for k, v in sorted(LOST.items()))
    warn(f"perf tamponu tasti, {total} olay kayboldu ({detail}). --perf-pages degerini artirin.")


def find_libssl():
    multiarch = ("x86_64-linux-gnu", "aarch64-linux-gnu")
    paths = []
    for ver in ("3", "1.1"):
        for base in ("/lib64", "/usr/lib64"):
            paths.append(f"{base}/libssl.so.{ver}")
        for arch in multiarch:
            paths.append(f"/lib/{arch}/libssl.so.{ver}")
            paths.append(f"/usr/lib/{arch}/libssl.so.{ver}")
    for path in paths:
        if os.path.exists(path):
            return path
    try:
        out = subprocess.check_output(["ldconfig", "-p"], text=True, stderr=subprocess.DEVNULL)
        cands = []
        for line in out.splitlines():
            if "libssl.so" in line and "=>" in line:
                cand = line.split("=>")[-1].strip()
                if os.path.exists(cand):
                    cands.append(cand)
        # .so.3 > .so.1.1 > digerleri
        for pref in ("libssl.so.3", "libssl.so.1.1"):
            for cand in cands:
                if os.path.basename(cand) == pref:
                    return cand
        if cands:
            return cands[0]
    except Exception:
        pass
    return None


def compile_bpf():
    """BPF'yi derler; olmazsa daha dar moda duser. Doner: (bpf, yasam_dongusu, bayt, udp_derlendi)."""
    base = [f"-DUDP_WINDOW_NS={int(ARGS.udp_window * 1e9)}ULL"]
    if ARGS.no_lifecycle:
        modes = [(["-DNO_LIFECYCLE"], False, False)]
    else:
        modes = []
        if not ARGS.no_bytes:
            modes.append(([], True, True))
        modes.append((["-DNO_BYTES"], True, False))
        modes.append((["-DNO_LIFECYCLE"], False, False))
    attempts = []
    for udp in ([True, False] if not ARGS.no_udp else [False]):
        for flags, life, byt in modes:
            attempts.append((base + flags + ([] if udp else ["-DNO_UDP"]), life, byt, udp))
    last = None
    for i, (flags, life, byt, udp) in enumerate(attempts):
        try:
            return BPF(text=BPF_PROGRAM, cflags=flags), life, byt, udp
        except Exception as e:
            last = e
            warn(f"BPF derlenemedi/baglanamadi (bayraklar: {' '.join(flags)}): {e}")
            if i + 1 < len(attempts):
                warn("daha dar bir mod deneniyor...")
    raise last


def attach_udp():
    """UDP kprobe'larini baglar. Doner: IPv4 UDP (udp_sendmsg) baglandi mi."""
    try:
        b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
        b.attach_kretprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg_ret")
    except Exception as e:
        warn(f"udp_sendmsg probe eklenemedi ({e}); UDP akislari ve DNS surec eslemesi kapali.")
        return False
    try:
        b.attach_kprobe(event="udpv6_sendmsg", fn_name="trace_udpv6_sendmsg")
        b.attach_kretprobe(event="udpv6_sendmsg", fn_name="trace_udp_sendmsg_ret")
    except Exception as e:
        warn(f"udpv6_sendmsg probe eklenemedi ({e}); IPv6 UDP izlenmiyor.")
    return True


# ---------------------------------------------------------------------- main
def main():
    global b, LIFECYCLE_ON, BYTES_ON, UDP_ON, DNS_ON, PKT_SOCK
    print_banner()
    LOGGERS["outbound"] = make_logger("sniper.outbound", OUT_LOG)
    LOGGERS["inbound"] = make_logger("sniper.inbound", IN_LOG)

    b, LIFECYCLE_ON, BYTES_ON, udp_compiled = compile_bpf()
    if not LIFECYCLE_ON and not ARGS.no_lifecycle:
        warn("yasam dongusu (close kaydi) kapali: tracepoint sock:inet_sock_set_state kullanilamadi.")
    elif LIFECYCLE_ON and not BYTES_ON and not ARGS.no_bytes:
        warn("bayt sayaclari okunamadi (cekirdek < 4.19?); close kayitlarinda bytes_tx/bytes_rx bos olacak.")
    if not udp_compiled and not ARGS.no_udp:
        warn("UDP bolumu derlenemedi; UDP akislari ve DNS surec eslemesi kapali.")

    for sym in ("tcp_v4_connect", "tcp_v6_connect"):
        b.attach_kprobe(event=sym, fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_accept_return")

    host_sources = []
    if ENABLE_HOST_ENRICHMENT:
        try:
            b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo")
            host_sources.append("dns")
        except Exception as e:
            warn(f"getaddrinfo probe eklenemedi ({e}); host_guess icin DNS kaynagi yok.")
        libssl = find_libssl()
        if libssl:
            try:
                b.attach_uprobe(name=libssl, sym="SSL_ctrl", fn_name="trace_ssl_ctrl")
                host_sources.append("sni")
            except Exception as e:
                warn(f"SNI probe eklenemedi ({libssl}: {e}); host_guess yalnizca dns olacak.")
        else:
            warn("libssl bulunamadi; SNI probe atlandi, host_guess yalnizca dns olacak.")

    UDP_ON = attach_udp() if udp_compiled else False

    pages = ARGS.perf_pages
    for name, direction, family in (
        ("ipv4_out_events", "outbound", "ipv4"),
        ("ipv6_out_events", "outbound", "ipv6"),
        ("ipv4_in_events", "inbound", "ipv4"),
        ("ipv6_in_events", "inbound", "ipv6"),
    ):
        b[name].open_perf_buffer(make_open_cb(name, direction, family),
                                 page_cnt=pages, lost_cb=make_lost_cb(name))
    b["host_events"].open_perf_buffer(host_cb, page_cnt=pages, lost_cb=make_lost_cb("host_events"))
    if LIFECYCLE_ON:
        b["close_events"].open_perf_buffer(close_cb, page_cnt=pages, lost_cb=make_lost_cb("close_events"))
    if UDP_ON:
        b["udp_events"].open_perf_buffer(udp_cb, page_cnt=pages, lost_cb=make_lost_cb("udp_events"))

    if not ARGS.no_dns:
        try:
            PKT_SOCK = open_dns_socket()
            DNS_ON = True
        except Exception as e:
            warn(f"DNS paket yakalama baslatilamadi ({e}); DNS kayitlari kapali.")
        if DNS_ON and not UDP_ON:
            warn("UDP akis olaylari yok: DNS kayitlarinda surec (pid/comm) bilinmeyecek.")
    refresh_local_addrs(force=True)

    print(f"sniper v{VERSION} basladi (monitor-only, format={ARGS.format}).", flush=True)
    print(f"  giden : {OUT_LOG}", flush=True)
    print(f"  gelen : {IN_LOG}", flush=True)
    if ARGS.format == "csv":
        d = "TAB" if CSV_DELIM == "\t" else CSV_DELIM
        print(f"  csv   : ayirac='{d}' bom={ARGS.csv_bom} excel-safe={ARGS.csv_excel_safe}", flush=True)
    print(f"  cmdline: {'kapali (acmak icin --cmd)' if ARGS.no_cmd else 'acik'}", flush=True)
    if ENABLE_HOST_ENRICHMENT:
        print(f"  host_guess kaynaklari: {', '.join(host_sources) if host_sources else 'yok'}"
              f"{' + dns-yaniti' if DNS_ON else ''}", flush=True)
    print(f"  yasam dongusu: {'acik' if LIFECYCLE_ON else 'kapali'}"
          f"{' (bayt sayaclari ' + ('acik' if BYTES_ON else 'kapali') + ')' if LIFECYCLE_ON else ''}", flush=True)
    print(f"  udp: {'acik (pencere ' + format(ARGS.udp_window, 'g') + ' sn)' if UDP_ON else 'kapali'}"
          f" | dns: {'acik (AF_PACKET 53/udp, yerel adres: ' + str(len(LOCAL_ADDRS)) + ')' if DNS_ON else 'kapali'}",
          flush=True)
    print(f"  zenginlestirme: {'acik' if ENRICH else 'kapali'} | kurallar: {len(RULES)} "
          f"(varsayilan: {RULES_DEFAULT}) | dedupe: {ARGS.dedupe or 'kapali'}", flush=True)
    print(f"  perf-pages: {pages}", flush=True)
    if not ARGS.no_snapshot:
        try:
            n, skipped = take_snapshot()
            print(f"  snapshot: {n} acik baglanti kaydedildi ({skipped} atlandi; yon tahmindir)", flush=True)
        except Exception as e:
            warn(f"snapshot alinamadi: {e}")
    print(flush=True)

    try:
        while True:
            b.perf_buffer_poll(timeout=POLL_MS)
            drain_packets()
            process_pending()
            flush_dedupe()
            refresh_local_addrs()
            report_lost()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            drain_packets()
            process_pending(force=True)
            flush_dedupe(force=True)
        except Exception as e:
            print(f"kapanista isleme hatasi: {e}", file=sys.stderr, flush=True)
        report_lost(force=True)
        logging.shutdown()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    main()
