#!/usr/bin/env python3
"""
Безопасный лабораторный генератор тестовых сетевых паттернов для проверки NIDS.
Работает ТОЛЬКО с приватными локальными IP (192.168.x.x / 10.x.x.x / 172.16-31.x.x).

Сценарий на 5 минут (300 секунд):
  00:00 - 01:00  обычный фон (ты спокойно сёрфишь)
  01:00 - 01:30  [TEST 1] TCP-сканирование портов (SYN / RST / uniq_dst_ports_ratio)
  01:30 - 02:30  обычный фон
  02:30 - 03:00  [TEST 2] Мелкий UDP-поток (pps / udp_ratio / низкий len_std)
  03:00 - 03:45  обычный фон
  03:45 - 04:15  [TEST 3] Частый ICMP-поток (icmp_ratio)
  04:15 - 05:00  обычный фон

На выходе сохраняет ground_truth.json с точными метками времени для расчёта ROC-AUC / F1.

Запуск (сначала запусти dumpcap на 300 с, и сразу этот скрипт):
  py -3.12 simulate_lab_tests.py --target 192.168.1.1 --out ground_truth.json
"""
import argparse
import ipaddress
import json
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path


def validate_private_ip(ip_str: str) -> str:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        raise SystemExit(f"Некорректный IP-адрес: {ip_str}")
    if not addr.is_private or addr.is_loopback or addr.is_multicast:
        raise SystemExit(
            f"Отказ: адрес {ip_str} не является приватным локальным IP "
            "(разрешены только 192.168.x.x, 10.x.x.x, 172.16-31.x.x)."
        )
    return str(addr)


def fmt_local(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def wait_until(target_ts: float, label: str):
    rem = target_ts - time.time()
    if rem > 0:
        print(f"[{fmt_local(time.time())}] {label} ({rem:.0f} с)...")
        time.sleep(rem)


def run_tcp_port_probe(target: str, duration: float = 30.0):
    """Умеренный TCP-пробинг портов (только connect_ex с коротким таймаутом)."""
    end_ts = time.time() + duration
    sent = 0

    def probe(port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.04)
        try:
            s.connect_ex((target, port))
        except OSError:
            pass
        finally:
            s.close()

    port = 2000
    with ThreadPoolExecutor(max_workers=20) as pool:
        while time.time() < end_ts:
            batch = [((port + i - 2000) % 4000) + 2000 for i in range(20)]
            port += 20
            list(pool.map(probe, batch))
            sent += len(batch)
            time.sleep(0.08)
    return sent


def run_udp_small_stream(target: str, duration: float = 30.0, pps_target: int = 800):
    """Поток одинаковых мелких UDP-пакетов (ограничен по скорости, безопасен для локалки)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"NIDS_LAB_TEST_UDP_PKT_01"  # 24 байта
    end_ts = time.time() + duration
    batch_size = 20
    pause = batch_size / max(pps_target, 1)
    sent = 0
    try:
        while time.time() < end_ts:
            for _ in range(batch_size):
                try:
                    sock.sendto(payload, (target, 54321))
                    sent += 1
                except OSError:
                    pass
            time.sleep(pause)
    finally:
        sock.close()
    return sent


def run_icmp_stream(target: str, duration: float = 30.0):
    """Частый ICMP Echo-поток (через scapy, либо через системный ping)."""
    end_ts = time.time() + duration
    sent = 0
    try:
        from scapy.layers.inet import ICMP, IP
        from scapy.sendrecv import send

        pkt = IP(dst=target) / ICMP() / (b"X" * 32)
        while time.time() < end_ts:
            send(pkt, count=15, inter=0.01, verbose=False)
            sent += 15
            time.sleep(0.05)
        return sent
    except Exception:
        # Запасной вариант через системный ping, если нет прав на raw sockets
        def one_ping(_):
            subprocess.run(
                ["ping", "-n", "1", "-w", "150", "-l", "32", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            while time.time() < end_ts:
                list(pool.map(one_ping, range(8)))
                sent += 8
                time.sleep(0.1)
        return sent


def main():
    parser = argparse.ArgumentParser(
        description="Лабораторный 5-минутный автопрогон 3 тестовых сетевых паттернов."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Локальный приватный IP-адрес цели (например, ваш роутер 192.168.1.1 или локальная VM)",
    )
    parser.add_argument(
        "--out",
        default="ground_truth.json",
        help="Файл для сохранения точных интервалов времени (по умолчанию ground_truth.json)",
    )
    args = parser.parse_args()

    target = validate_private_ip(args.target)
    t0 = time.time()
    events = []

    print(f"Старт 5-минутного лабораторного сценария -> цель: {target}")
    print(f"Время старта: {fmt_local(t0)} (epoch={t0:.2f})")
    print("Сейчас спокойно пользуйся браузером как обычно — скрипт сам запустит тесты по таймеру.\n")

    schedule = [
        (60, 30, "tcp_port_probe", "TCP-сканирование портов", run_tcp_port_probe),
        (150, 30, "udp_small_stream", "Мелкий UDP-поток", run_udp_small_stream),
        (225, 30, "icmp_stream", "Частый ICMP-поток", run_icmp_stream),
    ]

    for start_offset, dur, code, title, fn in schedule:
        wait_until(t0 + start_offset, "Обычный фоновый трафик")
        ev_start = time.time()
        print(f"[{fmt_local(ev_start)}] >>> СТАРТ теста: {title} ({dur} с)...")
        sent = fn(target, dur)
        ev_end = time.time()
        print(f"[{fmt_local(ev_end)}] <<< СТОП теста: {title} (отправлено ~{sent} проб)\n")
        events.append(
            {
                "code": code,
                "title": title,
                "start_epoch": round(ev_start, 2),
                "end_epoch": round(ev_end, 2),
                "start_local": fmt_local(ev_start),
                "end_local": fmt_local(ev_end),
                "t_rel_start": round(ev_start - t0, 1),
                "t_rel_end": round(ev_end - t0, 1),
            }
        )

    wait_until(t0 + 300, "Финальный чистый хвост до 5:00")

    out_path = Path(args.out).resolve()
    payload = {
        "target": target,
        "script_start_epoch": round(t0, 2),
        "script_start_local": fmt_local(t0),
        "events": events,
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nГотово! Разметка времени сохранена в: {out_path}")


if __name__ == "__main__":
    main()