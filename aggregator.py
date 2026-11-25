#!/usr/bin/env python3
"""
Агрегатор pcap -> CSV: одна строка = одно окно (по умолчанию 1 секунда).

Установка:   pip install scapy
Запуск:      python aggregator.py file1.pcap file2.pcap            (можно маски: *.pcap)
Параметры:   --window 1.0            размер окна, сек
             --out features.csv      итоговая таблица признаков
             --suspicious suspicious.csv   окна с экстремальными значениями (слой 3)
             --local-ip 192.168.31.130     IP снимаемого ПК (по умолчанию определяется сам)
             --config settings.json  переопределить SETTINGS (см. ниже)
             --no-fill               не добавлять пустые окна (по умолчанию добавляются нулями)

             --model-out features_model.csv   только признаки для модели (без пустых окон)

Колонки: file, t_rel (сек от начала файла), t_start_epoch (unix-время начала окна, число),
time_utc (ISO, UTC), time_local (местное время ПК, на котором считали), дальше признаки.
Для сверки с журналом надёжнее всего t_rel + время первого пакета из Wireshark.
CSV не пересохраняйте в Excel/LibreOffice: даты портятся. Для просмотра есть отдельный вьюер.
"""
import argparse
import bisect
import csv
import glob
import ipaddress
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

# ---------------------------------------------------------------- настройки
SETTINGS = {
    "window_sec": 1.0,
    # границы корзин длины пакета (как в Wireshark -> Packet Lengths)
    "len_bins": [80, 160, 320, 640, 1280],
    "fill_empty": True,
    # слой 3: перцентиль и признаки для поиска выбросов (по всем файлам вместе)
    "percentile": 99.9,
    "suspicious_features": [
        "pps", "bps", "syn", "syn_share", "rst", "synack",
        "uniq_dst_ip", "uniq_dst_ports_out", "uniq_syn_targets",
        "arp", "icmp", "dns", "pkts_ext",
        "uniq_dst_ports_ratio", "uniq_in_syn_ports", "syn_close_ratio",
    ],
    "local_ip_probe_packets": 5000,
    # признаки, которые пойдут в модель (по результатам голосования команды, оценка 2).
    # Кандидаты со 1 голосом: len_min, len_mean, len_std, udp_ratio, icmp_ratio,
    # syn_close_ratio, payload_ratio. Список можно менять в --config.
    "model_features": [
        "pps", "bps", "len_max", "syn_share", "rst_share",
        "tcp_ratio", "uniq_dst_ports_ratio",
    ],
}

_private_cache = {}


def is_private(ip):
    v = _private_cache.get(ip)
    if v is None:
        try:
            v = ipaddress.ip_address(ip).is_private
        except ValueError:
            v = False
        _private_cache[ip] = v
    return v


# ---------------------------------------------------------------- разбор пакетов
def detect_local_ip(path, limit):
    """Самый частый приватный IPv4 среди первых пакетов (src и dst)."""
    cnt = Counter()
    with PcapReader(path) as rd:
        for i, pkt in enumerate(rd):
            if i >= limit:
                break
            ip = pkt.getlayer(IP)
            if ip is not None:
                for a in (ip.src, ip.dst):
                    if is_private(a) and not a.endswith(".255") and not a.startswith(("224.", "239.")):
                        cnt[a] += 1
    return cnt.most_common(1)[0][0] if cnt else None


def make_win():
    return {
        "pkts": 0, "bytes": 0, "lens": [], "ts": [],
        "pkts_in": 0, "pkts_out": 0, "pkts_ext": 0, "bytes_in": 0, "bytes_out": 0,
        "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "ipv6": 0, "other": 0,
        "syn": 0, "synack": 0, "fin": 0, "rst": 0,
        "dns": 0, "mdns": 0, "quic": 0, "tcp443": 0,
        "dst_ips": Counter(), "src_ips_in": set(), "dst_ports_out": set(),
        "syn_targets": set(), "flows": set(),
        "payload": 0, "dst_ports_all": set(), "in_syn_ports": set(),
    }


def tcp_payload(pkt, ip, ip6, tcp, n):
    """Полезные данные TCP-сегмента в байтах (без заголовков IP и TCP)."""
    hdr = (tcp.dataofs or 5) * 4
    if ip is not None and ip.len:
        return max(0, ip.len - (ip.ihl or 5) * 4 - hdr)
    if ip6 is not None and ip6.plen:
        return max(0, ip6.plen - hdr)
    return max(0, n - 14 - 20 - hdr)  # запасной вариант (например, len=0 при offload)


def process(pkt, w, local):
    n = getattr(pkt, "wirelen", None) or len(pkt)
    w["pkts"] += 1
    w["bytes"] += n
    w["lens"].append(n)
    w["ts"].append(float(pkt.time))

    if pkt.haslayer(ARP):
        w["arp"] += 1
        return

    ip = pkt.getlayer(IP)
    ip6 = None
    if ip is not None:
        src, dst = ip.src, ip.dst
        icmp = pkt.haslayer(ICMP)
    else:
        ip6 = pkt.getlayer(IPv6)
        if ip6 is None:
            w["other"] += 1
            return
        w["ipv6"] += 1
        src, dst = ip6.src, ip6.dst
        icmp = ip6.nh == 58

    out = src == local
    inn = dst == local
    if out:
        w["pkts_out"] += 1
        w["bytes_out"] += n
        w["dst_ips"][dst] += 1
    elif inn:
        w["pkts_in"] += 1
        w["bytes_in"] += n
        w["src_ips_in"].add(src)
    else:
        w["pkts_ext"] += 1  # чужие устройства: mDNS, SSDP, широковещание

    tcp = pkt.getlayer(TCP)
    udp = None if tcp else pkt.getlayer(UDP)
    sport = dport = None
    if tcp is not None:
        w["tcp"] += 1
        f = int(tcp.flags)
        syn, ack = f & 0x02, f & 0x10
        if syn and not ack:
            w["syn"] += 1
            if out:
                w["syn_targets"].add((dst, tcp.dport))
        elif syn and ack:
            w["synack"] += 1
        if f & 0x01:
            w["fin"] += 1
        if f & 0x04:
            w["rst"] += 1
        sport, dport = tcp.sport, tcp.dport
        if syn and not ack and inn:
            w["in_syn_ports"].add(dport)
        w["payload"] += tcp_payload(pkt, ip, ip6, tcp, n)
        if 443 in (sport, dport):
            w["tcp443"] += 1
        proto = "t"
    elif udp is not None:
        w["udp"] += 1
        sport, dport = udp.sport, udp.dport
        w["payload"] += max(0, (udp.len or 8) - 8)
        if 443 in (sport, dport):
            w["quic"] += 1
        proto = "u"
    elif icmp:
        w["icmp"] += 1
        proto = "i"
    else:
        w["other"] += 1
        proto = "o"

    if sport is not None:
        if 53 in (sport, dport):
            w["dns"] += 1
        if 5353 in (sport, dport):
            w["mdns"] += 1
        w["dst_ports_all"].add(dport)
        if out:
            w["dst_ports_out"].add(dport)
        w["flows"].add((proto,) + tuple(sorted([(src, sport), (dst, dport)])))


# ---------------------------------------------------------------- признаки окна
def entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum(c / total * math.log2(c / total) for c in counter.values())


def len_labels(bins):
    labels = [f"len_lt{bins[0]}"]
    for a, b in zip(bins, bins[1:]):
        labels.append(f"len_{a}_{b - 1}")
    labels.append(f"len_ge{bins[-1]}")
    return labels


def make_row(w, idx, t0, win, fname, bins):
    n = w["pkts"]
    lens = w["lens"]
    mean = sum(lens) / n if n else 0.0
    std = math.sqrt(sum((x - mean) ** 2 for x in lens) / n) if n else 0.0

    bin_counts = [0] * (len(bins) + 1)
    for x in lens:
        bin_counts[bisect.bisect_right(bins, x)] += 1

    ts = sorted(w["ts"])
    if len(ts) > 1:
        d = [b - a for a, b in zip(ts, ts[1:])]
        iat_mean = sum(d) / len(d)
        iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in d) / len(d))
    else:
        iat_mean = iat_std = 0.0

    tcp = w["tcp"]
    start = t0 + idx * win
    row = {
        "file": fname,
        "t_rel": round(idx * win, 3),
        "t_start_epoch": round(start, 3),
        "time_utc": datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_local": datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S"),
        "pkts": n,
        "bytes": w["bytes"],
        "pps": round(n / win, 3),
        "bps": round(w["bytes"] * 8 / win, 1),
        "pkts_out": w["pkts_out"], "pkts_in": w["pkts_in"], "pkts_ext": w["pkts_ext"],
        "bytes_out": w["bytes_out"], "bytes_in": w["bytes_in"],
        "out_share": round(w["pkts_out"] / n, 4) if n else 0,
        "tcp": tcp, "udp": w["udp"], "icmp": w["icmp"], "arp": w["arp"],
        "ipv6": w["ipv6"], "other": w["other"],
        "syn": w["syn"], "synack": w["synack"], "fin": w["fin"], "rst": w["rst"],
        "syn_share": round(w["syn"] / tcp, 4) if tcp else 0,
        "rst_share": round(w["rst"] / tcp, 4) if tcp else 0,
        "dns": w["dns"], "mdns": w["mdns"], "quic": w["quic"], "tcp443": w["tcp443"],
        "len_mean": round(mean, 2), "len_std": round(std, 2),
        "len_min": min(lens) if lens else 0, "len_max": max(lens) if lens else 0,
        "iat_mean": round(iat_mean, 6), "iat_std": round(iat_std, 6),
        "uniq_dst_ip": len(w["dst_ips"]),
        "uniq_src_ip_in": len(w["src_ips_in"]),
        "uniq_dst_ports_out": len(w["dst_ports_out"]),
        "uniq_syn_targets": len(w["syn_targets"]),
        "uniq_flows": len(w["flows"]),
        "dst_ip_entropy": round(entropy(w["dst_ips"]), 4),
        # доли протоколов (tcp_ratio + udp_ratio + icmp_ratio + прочее = 1)
        "tcp_ratio": round(tcp / n, 4) if n else 0,
        "udp_ratio": round(w["udp"] / n, 4) if n else 0,
        "icmp_ratio": round(w["icmp"] / n, 4) if n else 0,
        # SYN против закрывающих пакетов, ограничено [0, 1]: syn / (syn + fin + rst)
        "syn_close_ratio": round(w["syn"] / (w["syn"] + w["fin"] + w["rst"]), 4)
                           if (w["syn"] + w["fin"] + w["rst"]) else 0,
        # полезные данные TCP/UDP относительно всех байт окна
        "payload_bytes": w["payload"],
        "payload_ratio": round(w["payload"] / w["bytes"], 4) if w["bytes"] else 0,
        # уникальные порты назначения по всем пакетам (любое направление) и их доля от пакетов окна
        "uniq_dst_ports_all": len(w["dst_ports_all"]),
        "uniq_dst_ports_ratio": round(len(w["dst_ports_all"]) / n, 4) if n else 0,
        # диагностика входящего сканирования: сколько разных локальных портов получили чужой SYN
        "uniq_in_syn_ports": len(w["in_syn_ports"]),
    }
    for label, c in zip(len_labels(bins), bin_counts):
        row[label] = round(c / n, 4) if n else 0
    return row


# ---------------------------------------------------------------- файл целиком
def process_file(path, window, bins, fill_empty, local_ip, probe):
    local = local_ip or detect_local_ip(path, probe)
    if not local:
        sys.exit(f"{path}: не удалось определить локальный IP, укажите --local-ip")
    wins = {}
    t0 = None
    total = 0
    with PcapReader(path) as rd:
        for pkt in rd:
            t = float(pkt.time)
            if t0 is None:
                t0 = t
            idx = int((t - t0) // window)
            if idx < 0:
                idx = 0
            w = wins.get(idx)
            if w is None:
                w = wins[idx] = make_win()
            process(pkt, w, local)
            total += 1
            if total % 50000 == 0:
                print(f"  {path}: {total} пакетов...", file=sys.stderr)
    if not wins:
        print(f"{path}: пустой файл", file=sys.stderr)
        return [], local
    last = max(wins)
    fname = path.replace("\\", "/").split("/")[-1]
    rows = []
    for idx in range(last + 1):
        w = wins.get(idx)
        if w is None:
            if not fill_empty:
                continue
            w = make_win()
        rows.append(make_row(w, idx, t0, window, fname, bins))
    return rows, local


# ---------------------------------------------------------------- слой 3
def find_suspicious(rows, features, percentile):
    """Для каждого признака берём верхние K окон, K = (100 - percentile)% от числа окон, минимум 1.
    На маленькой выборке это даёт хотя бы самое экстремальное окно, на большой около 0.1%."""
    out = []
    k = max(1, math.ceil((100 - percentile) / 100 * len(rows)))
    for feat in features:
        ranked = sorted(rows, key=lambda r: r[feat], reverse=True)[:k]
        cutoff = ranked[-1][feat] if ranked else 0
        for rank, r in enumerate(ranked, 1):
            if r[feat] > 0:
                out.append({
                    "file": r["file"], "t_rel": r["t_rel"], "time_utc": r["time_utc"],
                    "feature": feat, "value": r[feat], "rank": rank, "cutoff": cutoff,
                    "journal_note": "",  # заполните вручную: чем объясняется
                })
    out.sort(key=lambda x: (x["file"], x["t_rel"], x["feature"]))
    return out


SUSPICIOUS_COLUMNS = ["file", "t_rel", "time_utc", "feature", "value", "rank", "cutoff", "journal_note"]


def write_csv(path, rows, columns=None):
    cols = columns or (list(rows[0].keys()) if rows else [])
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig: Excel открывает без кракозябр
        wr = csv.DictWriter(f, fieldnames=cols)
        wr.writeheader()
        wr.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="pcap -> CSV признаков по окнам")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--window", type=float)
    ap.add_argument("--out", default="features.csv")
    ap.add_argument("--suspicious", default="suspicious.csv")
    ap.add_argument("--model-out", default="features_model.csv")
    ap.add_argument("--local-ip")
    ap.add_argument("--config")
    ap.add_argument("--no-fill", action="store_true")
    a = ap.parse_args()

    if a.config:
        with open(a.config, encoding="utf-8") as f:
            SETTINGS.update(json.load(f))
    if a.window:
        SETTINGS["window_sec"] = a.window
    if a.no_fill:
        SETTINGS["fill_empty"] = False

    paths = []
    for p in a.files:
        paths.extend(sorted(glob.glob(p)) or [p])

    all_rows = []
    for p in paths:
        rows, local = process_file(
            p, SETTINGS["window_sec"], SETTINGS["len_bins"], SETTINGS["fill_empty"],
            a.local_ip, SETTINGS["local_ip_probe_packets"])
        pk = sum(r["pkts"] for r in rows)
        empty = sum(1 for r in rows if r["pkts"] == 0)
        print(f"{p}: локальный IP {local}, окон {len(rows)} (пустых {empty}), пакетов {pk}")
        big = max((r["len_max"] for r in rows), default=0)
        if big > 1514:
            print(f"  ВНИМАНИЕ: есть кадры {big} байт (> 1514): похоже на offload, признаки размера искажены")
        all_rows.extend(rows)

    write_csv(a.out, all_rows)
    mf = SETTINGS["model_features"]
    bad = [f for f in mf if all_rows and f not in all_rows[0]]
    if bad:
        sys.exit(f"model_features: нет таких колонок: {bad}")
    model_rows = [{"file": r["file"], "t_rel": r["t_rel"], "t_start_epoch": r["t_start_epoch"],
                   **{f: r[f] for f in mf}} for r in all_rows if r["pkts"] > 0]
    write_csv(a.model_out, model_rows, ["file", "t_rel", "t_start_epoch"] + mf)
    print(f"Для модели: {a.model_out} ({len(model_rows)} строк, пустые окна исключены)")
    sus = find_suspicious(all_rows, SETTINGS["suspicious_features"], SETTINGS["percentile"])
    write_csv(a.suspicious, sus, SUSPICIOUS_COLUMNS)
    print(f"Записано: {a.out} ({len(all_rows)} строк), {a.suspicious} ({len(sus)} записей)")


if __name__ == "__main__":
    main()
