#!/usr/bin/env python3
"""
Боевой детектор сетевых аномалий NIDS на базе обученного автоэнкодера
(TensorFlow/Keras + scikit-learn).

Поддерживает 3 режима работы:
  1. Проверка готового дампа (.pcap / .pcapng):
     py -3.12 detector.py --pcap "attack_test.pcapng" --model-dir model
  2. Перехват трафика в реальном времени (--live):
     py -3.12 detector.py --list-ifaces
     py -3.12 detector.py --live --iface "Беспроводная сеть" --model-dir model
  3. Быстрая проверка по уже готовой таблице features.csv:
     py -3.12 detector.py --csv "3 часть/features.csv" --model-dir model

Опции:
  --threshold 0.0259   переопределить порог MSE (по умолчанию берётся threshold_p99 из config.json)
  --streak 2           сколько секунд подряд MSE должен быть выше порога для тревоги (по умолч. 2)
  --out detections.csv сохранить пооконный лог детекций в CSV
"""
import argparse
import json
import math
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


class WindowAggregator:
    """Агрегатор 1-секундных окон с формулами, идентичными aggregator.py (14 признаков)."""

    def __init__(self, window_sec: float = 1.0):
        self.window_sec = window_sec
        self.reset()

    def reset(self):
        self.pkts = 0
        self.bytes = 0
        self.lens = []
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.syn = 0
        self.fin = 0
        self.rst = 0
        self.payload = 0
        self.dst_ports = set()

    def add_packet(self, pkt):
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP

        n = getattr(pkt, "wirelen", None) or len(pkt)
        self.pkts += 1
        self.bytes += n
        self.lens.append(n)

        if pkt.haslayer(ARP):
            return

        ip = pkt.getlayer(IP)
        ip6 = None
        if ip is not None:
            is_icmp = pkt.haslayer(ICMP)
        else:
            ip6 = pkt.getlayer(IPv6)
            if ip6 is None:
                return
            is_icmp = ip6.nh == 58

        if is_icmp:
            self.icmp += 1

        tcp = pkt.getlayer(TCP)
        if tcp is not None:
            self.tcp += 1
            self.dst_ports.add(int(tcp.dport))
            flags = int(tcp.flags)
            if (flags & 0x12) == 0x02:  # SYN без ACK
                self.syn += 1
            if flags & 0x01:
                self.fin += 1
            if flags & 0x04:
                self.rst += 1

            hdr = (tcp.dataofs or 5) * 4
            if ip is not None and ip.len:
                pl = max(0, ip.len - (ip.ihl or 5) * 4 - hdr)
            elif ip6 is not None and ip6.plen:
                pl = max(0, ip6.plen - hdr)
            else:
                pl = max(0, n - 14 - 20 - hdr)
            self.payload += pl
            return

        udp = pkt.getlayer(UDP)
        if udp is not None:
            self.udp += 1
            self.dst_ports.add(int(udp.dport))
            if udp.len:
                self.payload += max(0, int(udp.len) - 8)
            else:
                self.payload += max(0, n - 14 - 20 - 8)

    def to_feature_dict(self) -> dict:
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


class AnomalyDetector:
    """Обёртка над scaler.pkl + autoencoder.keras + config.json."""

    def __init__(self, model_dir: Path, threshold: float = None, streak: int = None):
        from tensorflow import keras

        cfg_path = model_dir / "config.json"
        self.config = json.loads(cfg_path.read_text(encoding="utf-8"))
        self.features = self.config["features"]
        self.threshold = (
            float(threshold)
            if threshold is not None
            else float(self.config["threshold_p99"])
        )
        self.streak_need = (
            int(streak)
            if streak is not None
            else int(self.config.get("consecutive_alerts", 2))
        )
        self.scaler = joblib.load(model_dir / "scaler.pkl")
        self.model = keras.models.load_model(model_dir / "autoencoder.keras")

    def score_dataframe(self, df: pd.DataFrame):
        X = self.scaler.transform(df[self.features]).astype(np.float32)
        X_pred = self.model.predict(X, verbose=0)
        sq_err = (X - X_pred) ** 2
        mse = np.mean(sq_err, axis=1)
        return mse, sq_err, X, X_pred

    def explain_row(self, sq_err_row: np.ndarray, x_row: np.ndarray, pred_row: np.ndarray, top_k: int = 3) -> str:
        idx = np.argsort(sq_err_row)[::-1][:top_k]
        parts = []
        for i in idx:
            name = self.features[i]
            parts.append(f"{name} ({x_row[i]:.2f} vs {pred_row[i]:.2f})")
        return ", ".join(parts)


def run_batch(detector: AnomalyDetector, df: pd.DataFrame, out_csv: Path = None):
    if df.empty:
        print("Нет непустых окон для анализа.")
        return

    mse, sq_err, X, X_pred = detector.score_dataframe(df)
    above = mse > detector.threshold

    streak = 0
    alerts = []
    reasons = []
    for i in range(len(df)):
        if above[i]:
            streak += 1
        else:
            streak = 0
        is_alert = streak >= detector.streak_need
        alerts.append(is_alert)
        if is_alert:
            reasons.append(detector.explain_row(sq_err[i], X[i], X_pred[i]))
        else:
            reasons.append("")

    alerts_arr = np.array(alerts, dtype=bool)
    n = len(df)
    n_single = int(above.sum())
    n_alerts = int(alerts_arr.sum())

    print("\n" + "=" * 72)
    print(f"Окон проанализировано : {n}")
    print(f"Порог MSE             : {detector.threshold:.6f} (подряд >= {detector.streak_need} с)")
    print(f"Медиана / Макс MSE    : {np.median(mse):.6f} / {np.max(mse):.6f}")
    print(f"Превышений (1 с)      : {n_single} ({n_single / n * 100:.2f}%)")
    print(f"Тревог ({detector.streak_need}+ с подряд) : {n_alerts} ({n_alerts / n * 100:.2f}%)")
    print("=" * 72)

    if n_alerts > 0:
        print("\nЗафиксированные тревоги (первые 25):")
        shown = 0
        for i in range(n):
            if alerts_arr[i]:
                t_rel = df["t_rel"].iloc[i] if "t_rel" in df.columns else i
                t_loc = df["time_local"].iloc[i] if "time_local" in df.columns else ""
                print(f"  [ALERT] t={t_rel:6.0f}s {t_loc} | MSE={mse[i]:.5f} | {reasons[i]}")
                shown += 1
                if shown >= 25:
                    if n_alerts > 25:
                        print(f"  ... и ещё {n_alerts - 25} тревог (см. --out CSV)")
                    break
    else:
        print("\nАномалий не обнаружено — трафик в пределах нормы.")

    if out_csv:
        res = df[["t_rel", "time_local"]].copy() if "time_local" in df.columns else pd.DataFrame({"t_rel": range(n)})
        res["mse"] = np.round(mse, 6)
        res["above_threshold"] = above
        res["is_alert"] = alerts_arr
        res["top_reasons"] = reasons
        res.to_csv(out_csv, index=False)
        print(f"\nПодробный лог сохранён в: {out_csv.resolve()}")


def run_pcap(detector: AnomalyDetector, pcap_path: Path, window_sec: float, out_csv: Path = None):
    from scapy.utils import PcapReader

    if not pcap_path.exists():
        raise SystemExit(f"Файл не найден: {pcap_path}")

    print(f"Читаю дамп {pcap_path.name} (окно {window_sec:.1f} с)...")
    rows = []
    agg = WindowAggregator(window_sec=window_sec)
    t0 = None
    cur_win = 0

    def flush(win_idx):
        feats = agg.to_feature_dict()
        if feats:
            ts = t0 + win_idx * window_sec
            feats["t_rel"] = float(win_idx * window_sec)
            feats["time_local"] = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            rows.append(feats)
        agg.reset()

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            pt = float(pkt.time)
            if t0 is None:
                t0 = pt
            win_idx = int((pt - t0) // window_sec)
            if win_idx > cur_win:
                flush(cur_win)
                cur_win = win_idx
            agg.add_packet(pkt)
    if t0 is not None:
        flush(cur_win)

    df = pd.DataFrame(rows)
    run_batch(detector, df, out_csv=out_csv)


def run_live(detector: AnomalyDetector, iface: str, window_sec: float, out_csv: Path = None):
    from scapy.all import sniff

    print(
        f"Запуск мониторинга в реальном времени | интерфейс: {iface or 'по умолчанию'} | "
        f"порог MSE={detector.threshold:.6f} ({detector.streak_need} с подряд)"
    )
    print("Для остановки нажмите Ctrl + C.\n")

    streak = 0
    log_rows = []
    win_num = 0

    try:
        while True:
            agg = WindowAggregator(window_sec=window_sec)
            t_start = time.time()
            sniff(
                iface=iface,
                prn=agg.add_packet,
                store=False,
                timeout=window_sec,
            )
            now_str = datetime.fromtimestamp(t_start).strftime("%H:%M:%S")
            feats = agg.to_feature_dict()
            win_num += 1

            if not feats:
                streak = 0
                print(f"[{now_str}] IDLE   | pkts=0")
                continue

            row_df = pd.DataFrame([feats])
            mse_arr, sq_err, X, X_pred = detector.score_dataframe(row_df)
            mse_val = float(mse_arr[0])

            if mse_val > detector.threshold:
                streak += 1
            else:
                streak = 0

            is_alert = streak >= detector.streak_need
            if is_alert:
                reason = detector.explain_row(sq_err[0], X[0], X_pred[0])
                print(
                    f"[{now_str}] ALERT! | MSE={mse_val:.5f} (> {detector.threshold:.5f}) | "
                    f"pps={feats['pps']:.0f}, bps={feats['bps']/1e6:.2f} Мбит/с | {reason}"
                )
            else:
                reason = ""
                mark = "WARN  " if mse_val > detector.threshold else "OK    "
                print(
                    f"[{now_str}] {mark} | MSE={mse_val:.5f} | "
                    f"pps={feats['pps']:.0f}, bps={feats['bps']/1e6:.2f} Мбит/с, "
                    f"TCP={feats['tcp_ratio']*100:.0f}%, SYN={feats['syn_share']*100:.1f}%"
                )

            if out_csv:
                log_rows.append(
                    {
                        "t_rel": win_num * window_sec,
                        "time_local": now_str,
                        "mse": round(mse_val, 6),
                        "is_alert": is_alert,
                        "top_reasons": reason,
                    }
                )
    except KeyboardInterrupt:
        print("\nМониторинг остановлен.")
        if out_csv and log_rows:
            pd.DataFrame(log_rows).to_csv(out_csv, index=False)
            print(f"Лог сохранён в: {out_csv.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Боевой детектор аномалий NIDS (pcap / csv / live).")
    parser.add_argument("--model-dir", default="model", help="Папка с scaler.pkl, autoencoder.keras и config.json")
    parser.add_argument("--pcap", help="Режим 1: проверить готовый .pcap / .pcapng файл")
    parser.add_argument("--csv", help="Режим 2: быстро проверить уже готовый features.csv")
    parser.add_argument("--live", action="store_true", help="Режим 3: перехват трафика в реальном времени")
    parser.add_argument("--iface", default=None, help="Имя сетевого интерфейса для --live")
    parser.add_argument("--list-ifaces", action="store_true", help="Показать доступные интерфейсы scapy и выйти")
    parser.add_argument("--window", type=float, default=1.0, help="Размер окна в секундах (по умолчанию 1.0)")
    parser.add_argument("--threshold", type=float, default=None, help="Свой порог MSE (по умолчанию p99 из config.json)")
    parser.add_argument("--streak", type=int, default=None, help="Сколько секунд подряд выше порога для тревоги")
    parser.add_argument("--out", help="Сохранить результаты в CSV (например, detections.csv)")
    args = parser.parse_args()

    if args.list_ifaces:
        from scapy.all import show_interfaces
        show_interfaces()
        return

    if not any([args.pcap, args.csv, args.live]):
        parser.error("Укажите один из режимов: --pcap FILE, --csv FILE или --live")

    detector = AnomalyDetector(Path(args.model_dir), threshold=args.threshold, streak=args.streak)
    out_csv = Path(args.out) if args.out else None

    if args.csv:
        df = pd.read_csv(args.csv)
        if "pkts" in df.columns:
            df = df[df["pkts"] > 0].reset_index(drop=True)
        else:
            df = df[df["pps"] > 0].reset_index(drop=True)
        run_batch(detector, df, out_csv=out_csv)
    elif args.pcap:
        run_pcap(detector, Path(args.pcap), window_sec=args.window, out_csv=out_csv)
    elif args.live:
        run_live(detector, iface=args.iface, window_sec=args.window, out_csv=out_csv)


if __name__ == "__main__":
    main()