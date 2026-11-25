#!/usr/bin/env python3
r"""
NIDS SOC Admin Dashboard — локальный веб-сервер (FastAPI + WebSocket + tshark.exe + TensorFlow Autoencoder).

Запуск из папки G:\Мой диск\СОВ_НЕЙРОНКА\Данные\dashboard:
    py -3.12 server.py
    py -3.12 server.py --model-dir ..\model --tshark "D:\Wireshark\tshark.exe" --open
"""
import argparse
import asyncio
import csv
import io
import json
import math
import os
import random
import shutil
import subprocess
import tempfile
import threading
import time
import webbrowser
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Константы и 14 утверждённых признаков модели
# ---------------------------------------------------------------------------
DEFAULT_FEATURES = [
    "pps",
    "bps",
    "len_min",
    "len_max",
    "len_mean",
    "len_std",
    "syn_share",
    "rst_share",
    "syn_close_ratio",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "payload_ratio",
    "uniq_dst_ports_ratio",
]

PROTO_BUCKETS = ["TCP", "UDP", "QUIC", "DNS", "ICMP", "OTHER"]

TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "ip.proto",
    "ipv6.nxt",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "dns.qry.name",
    "arp.opcode",
    "_ws.col.Protocol",
    "_ws.col.Info",
]

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


def find_tshark(explicit: Optional[str] = None) -> Optional[str]:
    candidates = []
    if explicit:
        candidates.append(explicit)
    env_p = os.environ.get("TSHARK_PATH")
    if env_p:
        candidates.append(env_p)
    candidates.extend(
        [
            r"D:\Wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            shutil.which("tshark") or "",
        ]
    )
    for c in candidates:
        if c and Path(c).exists():
            return str(Path(c))
    return None


def find_model_dir(explicit: Optional[str] = None) -> Optional[Path]:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            BASE_DIR / "model",
            BASE_DIR.parent / "model",
            Path.cwd() / "model",
            Path.cwd().parent / "model",
        ]
    )
    for p in candidates:
        if p.exists() and (p / "config.json").exists():
            return p.resolve()
    return None


def find_test_dir() -> Optional[Path]:
    for p in [BASE_DIR / "test", BASE_DIR.parent / "test", Path.cwd() / "test", Path.cwd().parent / "test"]:
        if p.exists() and p.is_dir():
            return p.resolve()
    return None


def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.", "169.254.", "fe80:", "::1", "fc", "fd")):
        return True
    if ip.startswith("172."):
        try:
            oct2 = int(ip.split(".")[1])
            return 16 <= oct2 <= 31
        except Exception:
            return False
    return False


# ---------------------------------------------------------------------------
# Обёртка над обученным автоэнкодером (совместима с Detector.py)
# ---------------------------------------------------------------------------
class NIDSModelEngine:
    def __init__(self, model_dir: Optional[Path]):
        self.model_dir = model_dir
        self.loaded = False
        self.error: Optional[str] = None
        self.features = list(DEFAULT_FEATURES)
        self.threshold = 0.025915
        self.threshold_p99 = 0.025915
        self.threshold_p995 = 0.060073
        self.streak_need = 2
        self.scaler = None
        self.model = None
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if not self.model_dir:
            self.error = "Папка model/ не найдена (работа в режиме эвристики/демо)"
            return
        try:
            cfg_path = self.model_dir / "config.json"
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.features = cfg.get("features", list(DEFAULT_FEATURES))
            self.threshold_p99 = float(cfg.get("threshold_p99", 0.025915))
            self.threshold_p995 = float(cfg.get("threshold_p995", 0.060073))
            self.threshold = self.threshold_p99
            self.streak_need = int(cfg.get("consecutive_alerts", 2))

            import joblib
            from tensorflow import keras

            scaler_path = self.model_dir / "scaler.pkl"
            model_path = self.model_dir / "autoencoder.keras"
            with open(scaler_path, "rb") as f:
                self.scaler = joblib.load(f)
            try:
                self.model = keras.models.load_model(str(model_path))
            except Exception:
                # Обход бага TensorFlow/h5py с кириллицей в пути на Windows (G:\Мой диск\...)
                ascii_tmp = Path(tempfile.gettempdir()) / "nids_autoencoder_cached.keras"
                shutil.copy2(model_path, ascii_tmp)
                self.model = keras.models.load_model(str(ascii_tmp))
            self.loaded = True
            self.error = None
            print(f"  [OK] Модель загружена: {model_path.name} (порог p99={self.threshold:.6f})")
        except Exception as exc:
            self.loaded = False
            self.error = f"Модель не загружена: {exc}"
            print(f"  [WARN] {self.error}")

    def score_rows(self, rows: List[Dict[str, float]]) -> List[Dict[str, Any]]:
        if not rows:
            return []
        if self.loaded and self.scaler is not None and self.model is not None:
            import pandas as pd

            df = pd.DataFrame(rows)
            for col in self.features:
                if col not in df.columns:
                    df[col] = 0.0
            with self._lock:
                X = self.scaler.transform(df[self.features]).astype(np.float32)
                X_pred = self.model.predict(X, verbose=0)
            sq_err = (X - X_pred) ** 2
            mse_arr = np.mean(sq_err, axis=1)

            out = []
            for i in range(len(rows)):
                idx = np.argsort(sq_err[i])[::-1][:3]
                reasons = [
                    {
                        "feature": self.features[j],
                        "actual": round(float(X[i, j]), 4),
                        "recon": round(float(X_pred[i, j]), 4),
                        "err": round(float(sq_err[i, j]), 5),
                    }
                    for j in idx
                ]
                vec = [
                    {
                        "feature": self.features[j],
                        "raw": round(float(rows[i].get(self.features[j], 0.0)), 4),
                        "scaled": round(float(X[i, j]), 4),
                        "recon": round(float(X_pred[i, j]), 4),
                        "err": round(float(sq_err[i, j]), 5),
                    }
                    for j in range(len(self.features))
                ]
                out.append(
                    {
                        "mse": round(float(mse_arr[i]), 6),
                        "reasons": reasons,
                        "vector": vec,
                    }
                )
            return out

        # Фоллбек, если TF/model не загружены (чтобы дашборд всё равно работал)
        out = []
        for r in rows:
            syn = float(r.get("syn_share", 0.0))
            rst = float(r.get("rst_share", 0.0))
            icmp = float(r.get("icmp_ratio", 0.0))
            uports = float(r.get("uniq_dst_ports_ratio", 0.0))
            pps = float(r.get("pps", 0.0))
            mse = (
                0.0007
                + 0.055 * (rst ** 1.4)
                + 0.045 * (syn ** 1.5)
                + 0.040 * (icmp ** 1.4)
                + 0.030 * (uports ** 1.5)
                + (0.015 if pps > 2500 else 0.0)
            )
            vec = []
            for f in self.features:
                v = float(r.get(f, 0.0))
                scaled = min(1.0, math.log1p(max(0.0, v)) / 10.0) if f in ("pps", "bps") else min(1.0, v / 1514.0 if f.startswith("len_") else v)
                base = 0.02 if f in ("syn_share", "rst_share", "icmp_ratio") else scaled * 0.95
                vec.append(
                    {
                        "feature": f,
                        "raw": round(v, 4),
                        "scaled": round(scaled, 4),
                        "recon": round(base, 4),
                        "err": round((scaled - base) ** 2, 5),
                    }
                )
            top = sorted(vec, key=lambda x: x["err"], reverse=True)[:3]
            reasons = [{"feature": t["feature"], "actual": t["scaled"], "recon": t["recon"], "err": t["err"]} for t in top]
            out.append({"mse": round(mse, 6), "reasons": reasons, "vector": vec})
        return out


# ---------------------------------------------------------------------------
# Парсинг строк tshark и расчёт 1-секундных окон + протоколов + потоков
# ---------------------------------------------------------------------------
def parse_tshark_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < 19:
        parts.extend([""] * (19 - len(parts)))
    ts_s, flen_s, ip_proto, ipv6_nxt, ip_src, ip_dst, ip6_src, ip6_dst, tcp_sp, tcp_dp, tcp_fl, tcp_len, udp_sp, udp_dp, udp_len, dns_q, arp_op, ws_proto, ws_info = parts[:19]
    if not ts_s or not flen_s:
        return None
    try:
        ts = float(ts_s.split(",")[0])
        flen = int(flen_s.split(",")[0])
    except ValueError:
        return None

    src = ip_src.split(",")[0] or ip6_src.split(",")[0]
    dst = ip_dst.split(",")[0] or ip6_dst.split(",")[0]
    proto_num = (ip_proto.split(",")[0] or ipv6_nxt.split(",")[0]).strip()
    ws_p = (ws_proto or "").strip().upper()
    info = (ws_info or "").strip()

    is_arp = bool(arp_op) or ws_p == "ARP"
    is_tcp = bool(tcp_sp or tcp_dp) or proto_num == "6"
    is_udp = bool(udp_sp or udp_dp) or proto_num == "17"
    is_icmp = proto_num in ("1", "58") or "ICMP" in ws_p

    sport = None
    dport = None
    flags_int = 0
    payload = 0

    if is_tcp:
        try:
            sport = int(tcp_sp.split(",")[0]) if tcp_sp else None
            dport = int(tcp_dp.split(",")[0]) if tcp_dp else None
        except ValueError:
            pass
        if tcp_fl:
            try:
                fstr = tcp_fl.split(",")[0]
                flags_int = int(fstr, 16) if fstr.startswith("0x") else int(fstr)
            except ValueError:
                flags_int = 0
        if tcp_len:
            try:
                payload = max(0, int(tcp_len.split(",")[0]))
            except ValueError:
                payload = 0
    elif is_udp:
        try:
            sport = int(udp_sp.split(",")[0]) if udp_sp else None
            dport = int(udp_dp.split(",")[0]) if udp_dp else None
        except ValueError:
            pass
        if udp_len:
            try:
                payload = max(0, int(udp_len.split(",")[0]) - 8)
            except ValueError:
                payload = 0

    # Разделение на 6 обособленных протокольных окон (модель при этом считает сырые TCP/UDP/ICMP!)
    if is_icmp:
        bucket = "ICMP"
    elif "DNS" in ws_p or "MDNS" in ws_p or "LLMNR" in ws_p or bool(dns_q) or dport in (53, 5353) or sport in (53, 5353):
        bucket = "DNS"
    elif "QUIC" in ws_p or "TLS" in ws_p or "SSL" in ws_p or (is_udp and (dport in (443, 8443) or sport in (443, 8443))):
        bucket = "QUIC"
    elif is_tcp:
        bucket = "TCP"
    elif is_udp:
        bucket = "UDP"
    else:
        bucket = "OTHER"

    # Wireshark-стиль цвета события
    syn_only = is_tcp and ((flags_int & 0x12) == 0x02)
    rst_flag = is_tcp and bool(flags_int & 0x04)
    fin_flag = is_tcp and bool(flags_int & 0x01)

    if rst_flag:
        color = "rst"
    elif syn_only:
        color = "syn"
    elif bucket == "DNS":
        color = "dns"
    elif bucket == "QUIC":
        color = "quic"
    elif bucket == "ICMP":
        color = "icmp"
    elif bucket == "UDP":
        color = "udp"
    elif bucket == "TCP":
        color = "tcp"
    else:
        color = "arp"

    return {
        "ts": ts,
        "len": flen,
        "src": src or "L2",
        "dst": dst or "Broadcast",
        "sport": sport,
        "dport": dport,
        "is_arp": is_arp,
        "is_tcp": is_tcp,
        "is_udp": is_udp,
        "is_icmp": is_icmp,
        "syn": syn_only,
        "rst": rst_flag,
        "fin": fin_flag,
        "payload": payload,
        "bucket": bucket,
        "ws_proto": ws_p or bucket,
        "info": (info[:110] if info else (f"DNS {dns_q}" if dns_q else f"{ws_p or bucket} {flen} B")),
        "color": color,
    }


class RichWindowAggregator:
    """Агрегатор 1-секундного окна: 14 признаков для модели + 6 протоколов + потоки + события."""

    def __init__(self, window_sec: float = 1.0):
        self.window_sec = window_sec
        self.reset()

    def reset(self):
        self.pkts = 0
        self.bytes = 0
        self.lens: List[int] = []
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.syn = 0
        self.fin = 0
        self.rst = 0
        self.payload = 0
        self.dst_ports = set()

        self.bucket_counts = Counter()
        self.bucket_bytes = Counter()
        self.bucket_samples: Dict[str, List[Dict[str, Any]]] = {b: [] for b in PROTO_BUCKETS}
        self.events: List[Dict[str, Any]] = []
        self.flows: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}
        self.port_counts = Counter()
        self.host_bytes = Counter()
        self.directions = Counter()  # IN, OUT, LOCAL

    def add(self, p: Dict[str, Any]):
        n = p["len"]
        self.pkts += 1
        self.bytes += n
        self.lens.append(n)

        if not p["is_arp"]:
            if p["is_icmp"]:
                self.icmp += 1
            if p["is_tcp"]:
                self.tcp += 1
                if p["dport"] is not None:
                    self.dst_ports.add(p["dport"])
                if p["syn"]:
                    self.syn += 1
                if p["fin"]:
                    self.fin += 1
                if p["rst"]:
                    self.rst += 1
                self.payload += p["payload"]
            elif p["is_udp"]:
                self.udp += 1
                if p["dport"] is not None:
                    self.dst_ports.add(p["dport"])
                self.payload += p["payload"]

        b = p["bucket"]
        self.bucket_counts[b] += 1
        self.bucket_bytes[b] += n

        # Направление
        s_priv = is_private_ip(p["src"])
        d_priv = is_private_ip(p["dst"])
        if s_priv and d_priv:
            direction = "LOCAL"
        elif s_priv and not d_priv:
            direction = "OUT"
        else:
            direction = "IN"
        self.directions[direction] += 1

        # Потоки
        dp = p["dport"] or 0
        fkey = (p["src"], p["dst"], p["ws_proto"], dp)
        fl = self.flows.get(fkey)
        if fl is None:
            self.flows[fkey] = {
                "src": p["src"],
                "dst": p["dst"],
                "proto": p["ws_proto"],
                "bucket": b,
                "dport": dp,
                "pkts": 1,
                "bytes": n,
                "syn": 1 if p["syn"] else 0,
                "rst": 1 if p["rst"] else 0,
                "dir": direction,
            }
        else:
            fl["pkts"] += 1
            fl["bytes"] += n
            if p["syn"]:
                fl["syn"] += 1
            if p["rst"]:
                fl["rst"] += 1

        if dp:
            self.port_counts[dp] += 1
        if p["dst"]:
            self.host_bytes[p["dst"]] += n

        # Сэмплы событий (чтобы не перегружать браузер при 9000 pps)
        ev = {
            "time": datetime.fromtimestamp(p["ts"]).strftime("%H:%M:%S.%f")[:-3],
            "proto": p["ws_proto"],
            "bucket": b,
            "src": f"{p['src']}:{p['sport']}" if p["sport"] else p["src"],
            "dst": f"{p['dst']}:{p['dport']}" if p["dport"] else p["dst"],
            "len": n,
            "info": p["info"],
            "color": p["color"],
        }
        if len(self.bucket_samples[b]) < 6 or p["color"] in ("rst", "syn"):
            if len(self.bucket_samples[b]) < 10:
                self.bucket_samples[b].append(ev)
        if len(self.events) < 35 or p["color"] in ("rst", "syn", "icmp"):
            if len(self.events) < 60:
                self.events.append(ev)

    def to_features(self) -> Dict[str, float]:
        if self.pkts == 0:
            return {}
        mean_len = self.bytes / self.pkts
        var_len = sum((x - mean_len) ** 2 for x in self.lens) / self.pkts
        std_len = math.sqrt(var_len)
        syn_close_denom = self.syn + self.fin + self.rst
        return {
            "pps": self.pkts / self.window_sec,
            "bps": (self.bytes * 8.0) / self.window_sec,
            "len_min": float(min(self.lens)),
            "len_max": float(max(self.lens)),
            "len_mean": mean_len,
            "len_std": std_len,
            "syn_share": (self.syn / self.tcp) if self.tcp else 0.0,
            "rst_share": (self.rst / self.tcp) if self.tcp else 0.0,
            "syn_close_ratio": (self.syn / syn_close_denom) if syn_close_denom else 0.0,
            "tcp_ratio": self.tcp / self.pkts,
            "udp_ratio": self.udp / self.pkts,
            "icmp_ratio": self.icmp / self.pkts,
            "payload_ratio": (self.payload / self.bytes) if self.bytes else 0.0,
            "uniq_dst_ports_ratio": len(self.dst_ports) / self.pkts,
        }


# ---------------------------------------------------------------------------
# Менеджер Live-захвата (tshark.exe или Demo-симулятор)
# ---------------------------------------------------------------------------
class LiveCaptureManager:
    def __init__(self, engine: NIDSModelEngine, tshark_path: Optional[str]):
        self.engine = engine
        self.tshark_path = tshark_path
        self.running = False
        self.mode = "idle"  # idle | tshark | demo
        self.iface: Optional[str] = None
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.clients: List[WebSocket] = []

        self.demo_attack: Optional[str] = None
        self.demo_attack_until: float = 0.0

        self.streak = 0
        self.total_alerts = 0
        self.history: deque = deque(maxlen=120)
        self.alert_log: deque = deque(maxlen=100)
        self.flow_table: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop

    def broadcast(self, payload: Dict[str, Any]):
        if not self.loop or not self.clients:
            return
        msg = json.dumps(payload, ensure_ascii=False)
        for ws in list(self.clients):
            asyncio.run_coroutine_threadsafe(self._safe_send(ws, msg), self.loop)

    async def _safe_send(self, ws: WebSocket, msg: str):
        try:
            await ws.send_text(msg)
        except Exception:
            if ws in self.clients:
                self.clients.remove(ws)

    def start(self, mode: str, iface: Optional[str] = None):
        self.stop()
        self.running = True
        self.mode = mode
        self.iface = iface
        self.streak = 0
        if mode == "demo":
            self.thread = threading.Thread(target=self._demo_loop, daemon=True)
            self.thread.start()
        elif mode == "tshark":
            if not self.tshark_path:
                self.running = False
                self.mode = "idle"
                raise RuntimeError("tshark.exe не найден. Укажите путь или используйте Демо-режим.")
            self.thread = threading.Thread(target=self._tshark_loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        self.mode = "idle"
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None

    def _rolling_top_ports(self, limit: int = 6) -> List[Dict[str, Any]]:
        port_pkts: Counter = Counter()
        for fl in self.flow_table.values():
            dp = fl.get("dport") or 0
            if dp:
                port_pkts[dp] += fl.get("pkts", 0)
        return [{"port": p, "pkts": c} for p, c in port_pkts.most_common(limit)]

    def inject_demo_attack(self, kind: str, duration: float = 6.0):
        self.demo_attack = kind
        self.demo_attack_until = time.time() + duration

    def _emit_window(self, agg: RichWindowAggregator, ts_sec: float):
        now_str = datetime.fromtimestamp(ts_sec).strftime("%H:%M:%S")
        feats = agg.to_features()

        # Обновляем таблицу активных потоков (храним последние 30 с)
        now_t = time.time()
        for k, fl in agg.flows.items():
            prev = self.flow_table.get(k)
            if prev is None:
                fl["last_seen"] = now_t
                self.flow_table[k] = fl
            else:
                prev["pkts"] += fl["pkts"]
                prev["bytes"] += fl["bytes"]
                prev["syn"] += fl["syn"]
                prev["rst"] += fl["rst"]
                prev["last_seen"] = now_t
        stale = [k for k, v in self.flow_table.items() if now_t - v["last_seen"] > 30]
        for k in stale:
            del self.flow_table[k]

        if not feats:
            self.streak = 0
            snap = {
                "type": "tick",
                "time": now_str,
                "mode": self.mode,
                "iface": self.iface,
                "pkts": 0,
                "pps": 0.0,
                "mbps": 0.0,
                "mse": 0.0,
                "threshold": self.engine.threshold,
                "above": False,
                "is_alert": False,
                "streak": 0,
                "total_alerts": self.total_alerts,
                "reasons": [],
                "vector": [],
                "protocols": {b: {"pkts": 0, "bytes": 0, "samples": []} for b in PROTO_BUCKETS},
                "events": [],
                "flows": sorted(self.flow_table.values(), key=lambda x: x["bytes"], reverse=True)[:40],
                "top_ports": self._rolling_top_ports(6),
                "directions": {"LOCAL": 0, "OUT": 0, "IN": 0},
            }
            self.history.append({"time": now_str, "mse": 0.0, "pps": 0.0, "mbps": 0.0, "is_alert": False})
            self.broadcast(snap)
            return

        scored = self.engine.score_rows([feats])[0]
        mse = scored["mse"]
        above = mse > self.engine.threshold
        self.streak = (self.streak + 1) if above else 0
        is_alert = self.streak >= self.engine.streak_need

        events = list(agg.events)
        if is_alert:
            self.total_alerts += 1
            reason_txt = ", ".join(f"{r['feature']} ({r['actual']:.2f} vs {r['recon']:.2f})" for r in scored["reasons"])
            alert_item = {
                "time": now_str,
                "mse": mse,
                "threshold": self.engine.threshold,
                "pps": round(feats["pps"], 1),
                "mbps": round(feats["bps"] / 1e6, 2),
                "reasons": scored["reasons"],
                "summary": reason_txt,
            }
            self.alert_log.appendleft(alert_item)
            events.insert(
                0,
                {
                    "time": now_str,
                    "proto": "NIDS-ALERT",
                    "bucket": "TCP",
                    "src": "Autoencoder",
                    "dst": f"MSE={mse:.5f}",
                    "len": int(feats["pps"]),
                    "info": f"АНОМАЛИЯ ({self.streak}с подряд): {reason_txt}",
                    "color": "alert",
                },
            )

        snap = {
            "type": "tick",
            "time": now_str,
            "mode": self.mode,
            "iface": self.iface,
            "pkts": agg.pkts,
            "pps": round(feats["pps"], 1),
            "mbps": round(feats["bps"] / 1e6, 2),
            "mse": mse,
            "threshold": self.engine.threshold,
            "above": above,
            "is_alert": is_alert,
            "streak": self.streak,
            "total_alerts": self.total_alerts,
            "reasons": scored["reasons"],
            "vector": scored["vector"],
            "protocols": {
                b: {
                    "pkts": agg.bucket_counts.get(b, 0),
                    "bytes": agg.bucket_bytes.get(b, 0),
                    "samples": agg.bucket_samples.get(b, []),
                }
                for b in PROTO_BUCKETS
            },
            "events": events,
            "flows": sorted(self.flow_table.values(), key=lambda x: x["bytes"], reverse=True)[:40],
            "top_ports": self._rolling_top_ports(6),
            "directions": {
                "LOCAL": agg.directions.get("LOCAL", 0),
                "OUT": agg.directions.get("OUT", 0),
                "IN": agg.directions.get("IN", 0),
            },
        }
        self.history.append(
            {"time": now_str, "mse": mse, "pps": snap["pps"], "mbps": snap["mbps"], "is_alert": is_alert}
        )
        self.broadcast(snap)

    def _tshark_loop(self):
        cmd = [self.tshark_path, "-i", str(self.iface or "5"), "-l", "-n", "-T", "fields", "-E", "separator=\t"]
        for f in TSHARK_FIELDS:
            cmd.extend(["-e", f])

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            self.broadcast({"type": "error", "message": f"Не удалось запустить tshark: {exc}"})
            self.running = False
            self.mode = "idle"
            return

        agg = RichWindowAggregator(1.0)
        win_lock = threading.Lock()

        def reader():
            assert self.proc and self.proc.stdout
            for line in self.proc.stdout:
                if not self.running:
                    break
                pkt = parse_tshark_line(line)
                if pkt:
                    with win_lock:
                        agg.add(pkt)

        t_read = threading.Thread(target=reader, daemon=True)
        t_read.start()

        while self.running:
            time.sleep(1.0)
            if not self.running:
                break
            with win_lock:
                old = agg
                agg = RichWindowAggregator(1.0)
            self._emit_window(old, time.time())
            if self.proc and self.proc.poll() is not None:
                err_txt = ""
                if self.proc.stderr:
                    err_txt = self.proc.stderr.read()[:300]
                self.broadcast({"type": "error", "message": f"tshark завершился: {err_txt or 'код ' + str(self.proc.returncode)}"})
                self.running = False
                self.mode = "idle"
                break

    def _demo_loop(self):
        rng = random.Random()
        local_ip = "192.168.1.42"
        ext_hosts = ["142.250.74.78", "77.88.55.242", "104.18.26.120", "149.154.167.91", "1.1.1.1"]
        dns_names = ["youtube.com", "github.com", "yandex.ru", "google.com", "_googlecast._tcp.local"]

        while self.running:
            t_start = time.time()
            agg = RichWindowAggregator(1.0)
            attack = self.demo_attack if t_start < self.demo_attack_until else None
            if attack is None:
                self.demo_attack = None

            # Базовый нормальный фон (TCP HTTPS + QUIC + DNS/mDNS + ARP)
            n_tcp = rng.randint(45, 130)
            for _ in range(n_tcp):
                h = rng.choice(ext_hosts)
                flen = rng.choice([66, 124, 540, 1280, 1454, 1500])
                agg.add(
                    {
                        "ts": t_start,
                        "len": flen,
                        "src": h if rng.random() < 0.65 else local_ip,
                        "dst": local_ip if rng.random() < 0.65 else h,
                        "sport": 443,
                        "dport": rng.choice([443, 52412, 52418]),
                        "is_arp": False,
                        "is_tcp": True,
                        "is_udp": False,
                        "is_icmp": False,
                        "syn": False,
                        "rst": False,
                        "fin": False,
                        "payload": max(0, flen - 54),
                        "bucket": "TCP",
                        "ws_proto": "TLSv1.3",
                        "info": f"Application Data Len={max(0, flen - 54)}",
                        "color": "tcp",
                    }
                )
            for _ in range(rng.randint(25, 70)):
                h = rng.choice(ext_hosts[:2])
                flen = rng.randint(220, 1350)
                agg.add(
                    {
                        "ts": t_start,
                        "len": flen,
                        "src": h,
                        "dst": local_ip,
                        "sport": 443,
                        "dport": 55120,
                        "is_arp": False,
                        "is_tcp": False,
                        "is_udp": True,
                        "is_icmp": False,
                        "syn": False,
                        "rst": False,
                        "fin": False,
                        "payload": flen - 42,
                        "bucket": "QUIC",
                        "ws_proto": "QUIC",
                        "info": f"Protected Payload (KP0), Len={flen - 42}",
                        "color": "quic",
                    }
                )
            for _ in range(rng.randint(2, 6)):
                q = rng.choice(dns_names)
                is_mdns = q.endswith(".local")
                agg.add(
                    {
                        "ts": t_start,
                        "len": rng.randint(72, 130),
                        "src": local_ip,
                        "dst": "224.0.0.251" if is_mdns else "192.168.1.1",
                        "sport": 5353 if is_mdns else rng.randint(40000, 60000),
                        "dport": 5353 if is_mdns else 53,
                        "is_arp": False,
                        "is_tcp": False,
                        "is_udp": True,
                        "is_icmp": False,
                        "syn": False,
                        "rst": False,
                        "fin": False,
                        "payload": 48,
                        "bucket": "DNS",
                        "ws_proto": "MDNS" if is_mdns else "DNS",
                        "info": f"Standard query A {q}",
                        "color": "dns",
                    }
                )
            if rng.random() < 0.4:
                agg.add(
                    {
                        "ts": t_start,
                        "len": 42,
                        "src": "192.168.1.1",
                        "dst": "Broadcast",
                        "sport": None,
                        "dport": None,
                        "is_arp": True,
                        "is_tcp": False,
                        "is_udp": False,
                        "is_icmp": False,
                        "syn": False,
                        "rst": False,
                        "fin": False,
                        "payload": 0,
                        "bucket": "OTHER",
                        "ws_proto": "ARP",
                        "info": "Who has 192.168.1.42? Tell 192.168.1.1",
                        "color": "arp",
                    }
                )

            # Инъекция тестовой атаки в демо-режиме
            if attack == "portscan":
                for pnum in range(1, 220):
                    agg.add(
                        {
                            "ts": t_start,
                            "len": 54,
                            "src": "192.168.1.99",
                            "dst": local_ip,
                            "sport": 45123,
                            "dport": 1000 + pnum,
                            "is_arp": False,
                            "is_tcp": True,
                            "is_udp": False,
                            "is_icmp": False,
                            "syn": True,
                            "rst": False,
                            "fin": False,
                            "payload": 0,
                            "bucket": "TCP",
                            "ws_proto": "TCP",
                            "info": f"45123 -> {1000+pnum} [SYN] Seq=0 Win=1024",
                            "color": "syn",
                        }
                    )
                    agg.add(
                        {
                            "ts": t_start,
                            "len": 54,
                            "src": local_ip,
                            "dst": "192.168.1.99",
                            "sport": 1000 + pnum,
                            "dport": 45123,
                            "is_arp": False,
                            "is_tcp": True,
                            "is_udp": False,
                            "is_icmp": False,
                            "syn": False,
                            "rst": True,
                            "fin": False,
                            "payload": 0,
                            "bucket": "TCP",
                            "ws_proto": "TCP",
                            "info": f"{1000+pnum} -> 45123 [RST, ACK] Seq=1 Ack=1",
                            "color": "rst",
                        }
                    )
            elif attack == "icmp":
                for i in range(260):
                    agg.add(
                        {
                            "ts": t_start,
                            "len": 74,
                            "src": "192.168.1.99",
                            "dst": local_ip,
                            "sport": None,
                            "dport": None,
                            "is_arp": False,
                            "is_tcp": False,
                            "is_udp": False,
                            "is_icmp": True,
                            "syn": False,
                            "rst": False,
                            "fin": False,
                            "payload": 32,
                            "bucket": "ICMP",
                            "ws_proto": "ICMP",
                            "info": f"Echo (ping) request id=0x1337, seq={i}",
                            "color": "icmp",
                        }
                    )
            elif attack == "udp":
                for i in range(320):
                    dp = rng.randint(20000, 20050)
                    agg.add(
                        {
                            "ts": t_start,
                            "len": 64,
                            "src": "192.168.1.99",
                            "dst": local_ip,
                            "sport": 55555,
                            "dport": dp,
                            "is_arp": False,
                            "is_tcp": False,
                            "is_udp": True,
                            "is_icmp": False,
                            "syn": False,
                            "rst": False,
                            "fin": False,
                            "payload": 22,
                            "bucket": "UDP",
                            "ws_proto": "UDP",
                            "info": f"55555 -> {dp} Len=22",
                            "color": "udp",
                        }
                    )

            self._emit_window(agg, t_start)
            elapsed = time.time() - t_start
            time.sleep(max(0.05, 1.0 - elapsed))


# ---------------------------------------------------------------------------
# Анализ PCAP / PCAPNG дампов через tshark.exe
# ---------------------------------------------------------------------------
def analyze_pcap_file(pcap_path: Path, engine: NIDSModelEngine, tshark_path: Optional[str]) -> Dict[str, Any]:
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"Файл не найден: {pcap_path.name}")
    if not tshark_path:
        raise HTTPException(status_code=500, detail="tshark.exe не найден для разбора дампа.")

    cmd = [tshark_path, "-r", str(pcap_path), "-n", "-T", "fields", "-E", "separator=\t"]
    for f in TSHARK_FIELDS:
        cmd.extend(["-e", f])

    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    if res.returncode != 0 and not res.stdout.strip():
        raise HTTPException(status_code=400, detail=f"Ошибка tshark при чтении дампа: {res.stderr[:300]}")

    windows: Dict[int, RichWindowAggregator] = {}
    t0: Optional[float] = None
    total_pkts = 0
    total_bytes = 0
    proto_totals = Counter()
    proto_bytes = Counter()
    proto_samples: Dict[str, List[Dict[str, Any]]] = {b: [] for b in PROTO_BUCKETS}
    global_flows: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}
    global_ports = Counter()
    global_dirs = Counter()
    sample_events: List[Dict[str, Any]] = []

    for line in res.stdout.splitlines():
        p = parse_tshark_line(line)
        if not p:
            continue
        if t0 is None:
            t0 = p["ts"]
        win_idx = max(0, int(p["ts"] - t0))
        if win_idx not in windows:
            windows[win_idx] = RichWindowAggregator(1.0)
        windows[win_idx].add(p)

        total_pkts += 1
        total_bytes += p["len"]
        b = p["bucket"]
        proto_totals[b] += 1
        proto_bytes[b] += p["len"]

        s_priv, d_priv = is_private_ip(p["src"]), is_private_ip(p["dst"])
        direction = "LOCAL" if (s_priv and d_priv) else ("OUT" if s_priv else "IN")
        global_dirs[direction] += 1

        dp = p["dport"] or 0
        if dp:
            global_ports[dp] += 1
        fk = (p["src"], p["dst"], p["ws_proto"], dp)
        fl = global_flows.get(fk)
        if fl is None:
            global_flows[fk] = {
                "src": p["src"],
                "dst": p["dst"],
                "proto": p["ws_proto"],
                "bucket": b,
                "dport": dp,
                "pkts": 1,
                "bytes": p["len"],
                "syn": 1 if p["syn"] else 0,
                "rst": 1 if p["rst"] else 0,
                "dir": direction,
            }
        else:
            fl["pkts"] += 1
            fl["bytes"] += p["len"]
            if p["syn"]:
                fl["syn"] += 1
            if p["rst"]:
                fl["rst"] += 1

        ev = {
            "time": datetime.fromtimestamp(p["ts"]).strftime("%H:%M:%S.%f")[:-3],
            "proto": p["ws_proto"],
            "bucket": b,
            "src": f"{p['src']}:{p['sport']}" if p["sport"] else p["src"],
            "dst": f"{p['dst']}:{p['dport']}" if p["dport"] else p["dst"],
            "len": p["len"],
            "info": p["info"],
            "color": p["color"],
        }
        if len(proto_samples[b]) < 25:
            proto_samples[b].append(ev)
        if len(sample_events) < 250:
            sample_events.append(ev)

    if not windows:
        return {
            "filename": pcap_path.name,
            "windows": 0,
            "total_pkts": total_pkts,
            "message": "В дампе не найдено IP/Ethernet пакетов для анализа.",
        }

    sorted_keys = sorted(windows.keys())
    feat_rows = []
    meta_rows = []
    for k in sorted_keys:
        feats = windows[k].to_features()
        if not feats:
            continue
        feat_rows.append(feats)
        meta_rows.append(
            {
                "t_rel": k,
                "time_local": datetime.fromtimestamp((t0 or 0.0) + k).strftime("%Y-%m-%d %H:%M:%S"),
                "pkts": windows[k].pkts,
            }
        )

    scored = engine.score_rows(feat_rows)
    streak = 0
    timeline = []
    alerts = []
    mse_vals = []

    for i, sc in enumerate(scored):
        mse = sc["mse"]
        mse_vals.append(mse)
        above = mse > engine.threshold
        streak = (streak + 1) if above else 0
        is_alert = streak >= engine.streak_need
        reason_txt = ", ".join(f"{r['feature']} ({r['actual']:.2f} vs {r['recon']:.2f})" for r in sc["reasons"])
        item = {
            "t_rel": meta_rows[i]["t_rel"],
            "time": meta_rows[i]["time_local"],
            "pkts": meta_rows[i]["pkts"],
            "pps": round(feat_rows[i]["pps"], 1),
            "mbps": round(feat_rows[i]["bps"] / 1e6, 2),
            "mse": mse,
            "above": above,
            "is_alert": is_alert,
            "reasons": sc["reasons"],
            "summary": reason_txt if is_alert else "",
            "vector": sc["vector"],
        }
        timeline.append(item)
        if is_alert:
            alerts.append(item)

    return {
        "filename": pcap_path.name,
        "windows": len(timeline),
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "threshold": engine.threshold,
        "streak_need": engine.streak_need,
        "median_mse": round(float(np.median(mse_vals)), 6),
        "max_mse": round(float(np.max(mse_vals)), 6),
        "above_count": sum(1 for x in timeline if x["above"]),
        "alert_count": len(alerts),
        "timeline": timeline,
        "alerts": alerts,
        "protocols": {
            b: {
                "pkts": proto_totals.get(b, 0),
                "bytes": proto_bytes.get(b, 0),
                "samples": proto_samples.get(b, []),
            }
            for b in PROTO_BUCKETS
        },
        "flows": sorted(global_flows.values(), key=lambda x: x["bytes"], reverse=True)[:80],
        "top_ports": [{"port": p, "pkts": c} for p, c in global_ports.most_common(12)],
        "directions": {
            "LOCAL": global_dirs.get("LOCAL", 0),
            "OUT": global_dirs.get("OUT", 0),
            "IN": global_dirs.get("IN", 0),
        },
        "events": sample_events,
    }


# ---------------------------------------------------------------------------
# FastAPI приложение
# ---------------------------------------------------------------------------
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if LIVE is not None:
        LIVE.set_loop(asyncio.get_running_loop())
    yield


app = FastAPI(title="NIDS SOC Admin Dashboard", lifespan=lifespan)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ENGINE: Optional[NIDSModelEngine] = None
LIVE: Optional[LiveCaptureManager] = None
TSHARK_PATH: Optional[str] = None
TEST_DIR: Optional[Path] = None


class StartCaptureReq(BaseModel):
    mode: str = "tshark"  # tshark | demo
    iface: Optional[str] = None


class SettingsReq(BaseModel):
    threshold: Optional[float] = None
    streak: Optional[int] = None





@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
async def api_status():
    assert ENGINE and LIVE
    return {
        "model_loaded": ENGINE.loaded,
        "model_dir": str(ENGINE.model_dir) if ENGINE.model_dir else None,
        "model_error": ENGINE.error,
        "tshark_path": TSHARK_PATH,
        "threshold": ENGINE.threshold,
        "threshold_p99": ENGINE.threshold_p99,
        "threshold_p995": ENGINE.threshold_p995,
        "streak_need": ENGINE.streak_need,
        "running": LIVE.running,
        "mode": LIVE.mode,
        "iface": LIVE.iface,
        "total_alerts": LIVE.total_alerts,
        "history": list(LIVE.history),
        "alert_log": list(LIVE.alert_log),
    }


@app.get("/api/interfaces")
async def api_interfaces():
    if not TSHARK_PATH:
        return {"interfaces": [], "error": "tshark.exe не найден"}
    try:
        res = subprocess.run([TSHARK_PATH, "-D"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        items = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or "." not in line:
                continue
            idx, rest = line.split(".", 1)
            items.append({"id": idx.strip(), "label": rest.strip()})
        return {"interfaces": items, "error": None}
    except Exception as exc:
        return {"interfaces": [], "error": str(exc)}


@app.post("/api/capture/start")
async def api_start(req: StartCaptureReq):
    assert LIVE
    try:
        LIVE.start(mode=req.mode, iface=req.iface)
        return {"ok": True, "mode": LIVE.mode, "iface": LIVE.iface}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/capture/stop")
async def api_stop():
    assert LIVE
    LIVE.stop()
    return {"ok": True}


@app.post("/api/capture/inject")
async def api_inject(kind: str = Query("portscan")):
    assert LIVE
    if LIVE.mode != "demo":
        raise HTTPException(status_code=400, detail="Инъекция тестовой атаки доступна только в Демо-режиме.")
    LIVE.inject_demo_attack(kind, duration=6.0)
    return {"ok": True, "kind": kind}


@app.post("/api/settings")
async def api_settings(req: SettingsReq):
    assert ENGINE
    if req.threshold is not None and req.threshold > 0:
        ENGINE.threshold = float(req.threshold)
    if req.streak is not None and req.streak >= 1:
        ENGINE.streak_need = int(req.streak)
    return {"threshold": ENGINE.threshold, "streak_need": ENGINE.streak_need}


@app.get("/api/pcap/local-list")
async def api_pcap_local_list():
    files = []
    if TEST_DIR and TEST_DIR.exists():
        for p in sorted(TEST_DIR.iterdir()):
            if p.is_file() and p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
                files.append({"name": p.name, "size_kb": round(p.stat().st_size / 1024, 1)})
    return {"test_dir": str(TEST_DIR) if TEST_DIR else None, "files": files}


@app.post("/api/pcap/analyze-local")
async def api_pcap_analyze_local(name: str = Query(...)):
    assert ENGINE
    if not TEST_DIR:
        raise HTTPException(status_code=404, detail="Папка test/ не найдена")
    target = (TEST_DIR / Path(name).name).resolve()
    if not str(target).startswith(str(TEST_DIR.resolve())):
        raise HTTPException(status_code=400, detail="Некорректное имя файла")
    data = await asyncio.to_thread(analyze_pcap_file, target, ENGINE, TSHARK_PATH)
    return JSONResponse(data)


@app.post("/api/pcap/analyze")
async def api_pcap_upload(file: UploadFile = File(...)):
    assert ENGINE
    suffix = Path(file.filename or "upload.pcapng").suffix or ".pcapng"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        data = await asyncio.to_thread(analyze_pcap_file, tmp_path, ENGINE, TSHARK_PATH)
        data["filename"] = file.filename or tmp_path.name
        return JSONResponse(data)
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    assert LIVE
    await ws.accept()
    LIVE.clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in LIVE.clients:
            LIVE.clients.remove(ws)


def main():
    global ENGINE, LIVE, TSHARK_PATH, TEST_DIR
    parser = argparse.ArgumentParser(description="NIDS SOC Admin Dashboard")
    parser.add_argument("--model-dir", default=None, help="Путь к папке model/ (scaler.pkl, autoencoder.keras, config.json)")
    parser.add_argument("--tshark", default=None, help="Путь к tshark.exe (по умолчанию ищет D:\\Wireshark\\tshark.exe)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--open", action="store_true", help="Автоматически открыть браузер")
    args = parser.parse_args()

    TSHARK_PATH = find_tshark(args.tshark)
    model_dir = find_model_dir(args.model_dir)
    TEST_DIR = find_test_dir()

    print("=" * 68)
    print("  NIDS SOC Admin Dashboard")
    print(f"  Model dir : {model_dir or 'НЕ НАЙДЕНА (демо-режим)'}")
    print(f"  tshark    : {TSHARK_PATH or 'НЕ НАЙДЕН'}")
    print(f"  test dir  : {TEST_DIR or 'не найдена'}")
    print(f"  URL       : http://{args.host}:{args.port}")
    print("=" * 68)

    ENGINE = NIDSModelEngine(model_dir)
    LIVE = LiveCaptureManager(ENGINE, TSHARK_PATH)

    if args.open:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{args.host}:{args.port}")).start()

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
