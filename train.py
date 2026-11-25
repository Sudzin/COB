#!/usr/bin/env python3
"""
Обучение автоэнкодера NIDS на TensorFlow / Keras + scikit-learn (14 признаков).

Пайплайн нормализации (сохраняется в model/scaler.pkl через joblib):
  1. pps, bps -> np.clip(0, None) -> np.log1p -> MinMaxScaler(0, 1)
  2. len_min, len_max, len_mean, len_std -> np.clip(0, 1514) -> MinMaxScaler(0, 1)
  3. 8 долевых признаков -> уже в [0, 1], передаются как есть (passthrough)

Выходные файлы в папке --out-dir (по умолчанию model/):
  - scaler.pkl            обученный скейлер scikit-learn
  - autoencoder.keras     архитектура + веса автоэнкодера
  - autoencoder.weights.h5 отдельный файл весов
  - config.json           список признаков, пороги p99 / p99.5 и оценка FPR
  - loss_history.csv      история train_loss и val_loss по эпохам

Установка зависимостей:
  pip install tensorflow scikit-learn pandas numpy joblib

Запуск:
  python train.py --train train_5sessions_14f.csv --out-dir model
  python train.py --train train_6sessions_14f.csv --test-clean test_clean.csv --out-dir model
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, MinMaxScaler

LOG_MINMAX_COLS = ["pps", "bps"]
LEN_COLS = ["len_min", "len_max", "len_mean", "len_std"]
RATIO_COLS = [
    "syn_share",
    "rst_share",
    "syn_close_ratio",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "payload_ratio",
    "uniq_dst_ports_ratio",
]
FEATURES = LOG_MINMAX_COLS + LEN_COLS + RATIO_COLS
MTU_CAP = 1514.0


def build_scaler() -> ColumnTransformer:
    """Создаёт scikit-learn скейлер, который безопасно сохраняется в scaler.pkl."""
    log_pipe = Pipeline(
        steps=[
            ("nonneg", FunctionTransformer(np.clip, kw_args={"a_min": 0.0, "a_max": None})),
            ("log1p", FunctionTransformer(np.log1p)),
            ("minmax", MinMaxScaler(feature_range=(0.0, 1.0), clip=False)),
        ]
    )
    len_pipe = Pipeline(
        steps=[
            ("cap_mtu", FunctionTransformer(np.clip, kw_args={"a_min": 0.0, "a_max": MTU_CAP})),
            ("minmax", MinMaxScaler(feature_range=(0.0, 1.0), clip=False)),
        ]
    )
    ratio_pipe = FunctionTransformer(np.clip, kw_args={"a_min": 0.0, "a_max": 1.0})

    return ColumnTransformer(
        transformers=[
            ("log_rate", log_pipe, LOG_MINMAX_COLS),
            ("pkt_len", len_pipe, LEN_COLS),
            ("ratios", ratio_pipe, RATIO_COLS),
        ],
        remainder="drop",
    )


def build_autoencoder(input_dim: int = 14, latent_dim: int = 5):
    """Симметричный MLP-автоэнкодер на TensorFlow / Keras."""
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(input_dim,), name="traffic_features")
    x = layers.Dense(24, name="enc_1")(inp)
    x = layers.LeakyReLU(negative_slope=0.1)(x)
    x = layers.Dense(12, name="enc_2")(x)
    x = layers.LeakyReLU(negative_slope=0.1)(x)
    encoded = layers.Dense(latent_dim, name="bottleneck")(x)
    encoded = layers.LeakyReLU(negative_slope=0.1)(encoded)

    x = layers.Dense(12, name="dec_1")(encoded)
    x = layers.LeakyReLU(negative_slope=0.1)(x)
    x = layers.Dense(24, name="dec_2")(x)
    x = layers.LeakyReLU(negative_slope=0.1)(x)
    out = layers.Dense(input_dim, activation="linear", name="reconstructed")(x)

    model = keras.Model(inputs=inp, outputs=out, name="nids_autoencoder")
    return model


def consecutive_alert_rate(errors: np.ndarray, threshold: float, k: int = 2) -> float:
    """Доля окон, где порог превышен k секунд подряд (FPR со сглаживанием)."""
    above = (errors > threshold).astype(int)
    if len(above) < k:
        return 0.0
    streak = np.convolve(above, np.ones(k, dtype=int), mode="same")
    # Точный подсчёт скользящего окна длины k
    rolling = np.convolve(above, np.ones(k, dtype=int), mode="valid")
    return float((rolling == k).sum() / len(above))


def main():
    parser = argparse.ArgumentParser(
        description="Обучение автоэнкодера NIDS (TensorFlow/Keras + scikit-learn)."
    )
    parser.add_argument("--train", required=True, help="Путь к обучающему CSV")
    parser.add_argument("--test-clean", help="Опционально: чистый test CSV для калибровки порога")
    parser.add_argument("--out-dir", default="model", help="Папка для сохранения модели и скейлера")
    parser.add_argument("--epochs", type=int, default=120, help="Максимум эпох")
    parser.add_argument("--batch-size", type=int, default=128, help="Размер батча")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--patience", type=int, default=12, help="EarlyStopping patience")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    import tensorflow as tf
    from tensorflow import keras

    tf.random.set_seed(args.seed)
    np.random.seed(args.seed)

    df = pd.read_csv(args.train)
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise SystemExit(f"В файле нет столбцов: {missing}")

    if "pkts" in df.columns:
        df = df[df["pkts"] > 0].reset_index(drop=True)
    else:
        df = df[df["pps"] > 0].reset_index(drop=True)

    # Разбиение 80/20 по хвосту каждой сессии (без перемешивания соседних секунд)
    train_parts, val_parts = [], []
    if "session" in df.columns:
        for _, grp in df.groupby("session", sort=False):
            cut = int(len(grp) * 0.80)
            train_parts.append(grp.iloc[:cut])
            val_parts.append(grp.iloc[cut:])
        df_train = pd.concat(train_parts, ignore_index=True)
        df_val = pd.concat(val_parts, ignore_index=True)
    else:
        cut = int(len(df) * 0.80)
        df_train, df_val = df.iloc[:cut], df.iloc[cut:]

    # 1. Обучаем скейлер scikit-learn строго на train
    scaler = build_scaler()
    X_train = scaler.fit_transform(df_train[FEATURES]).astype(np.float32)
    X_val = scaler.transform(df_val[FEATURES]).astype(np.float32)

    print(f"Train: {X_train.shape} | Val: {X_val.shape}")
    print("Диапазоны признаков после scikit-learn MinMaxScaler (train):")
    for i, col in enumerate(FEATURES):
        print(
            f"  {col:<22s}: min={X_train[:, i].min():.3f}, "
            f"max={X_train[:, i].max():.3f}, med={np.median(X_train[:, i]):.3f}"
        )

    # 2. Создаём и обучаем автоэнкодер (TensorFlow / Keras)
    model = build_autoencoder(input_dim=len(FEATURES), latent_dim=5)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=args.lr),
        loss="mse",
    )

    early_stop = keras.callbacks.EarlyStopping(
        monitor="val_loss",
        patience=args.patience,
        restore_best_weights=True,
        verbose=1,
    )

    hist = model.fit(
        X_train,
        X_train,
        validation_data=(X_val, X_val),
        epochs=args.epochs,
        batch_size=args.batch_size,
        shuffle=True,
        callbacks=[early_stop],
        verbose=1,
    )

    # 3. Калибровка порога и оценка вероятности ложных срабатываний (FPR)
    if args.test_clean:
        df_cal = pd.read_csv(args.test_clean)
        df_cal = df_cal[df_cal["pps"] > 0].reset_index(drop=True)
        X_cal = scaler.transform(df_cal[FEATURES]).astype(np.float32)
        cal_source = args.test_clean
    else:
        X_cal = X_val
        cal_source = "val_split_20pct"

    X_pred = model.predict(X_cal, verbose=0)
    cal_errors = np.mean((X_cal - X_pred) ** 2, axis=1)

    thr_99 = float(np.percentile(cal_errors, 99.0))
    thr_995 = float(np.percentile(cal_errors, 99.5))
    fpr_p99_1s = float((cal_errors > thr_99).mean())
    fpr_p99_2s = consecutive_alert_rate(cal_errors, thr_99, k=2)
    fpr_p995_2s = consecutive_alert_rate(cal_errors, thr_995, k=2)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(scaler, out_dir / "scaler.pkl")
    model.save(out_dir / "autoencoder.keras")
    model.save_weights(out_dir / "autoencoder.weights.h5")

    best_val_loss = float(min(hist.history["val_loss"]))
    config = {
        "framework": "tensorflow.keras + scikit-learn",
        "input_dim": len(FEATURES),
        "latent_dim": 5,
        "features": FEATURES,
        "mtu_cap": MTU_CAP,
        "best_val_loss": round(best_val_loss, 6),
        "calibration_source": cal_source,
        "mse_median": round(float(np.median(cal_errors)), 6),
        "threshold_p99": round(thr_99, 6),
        "threshold_p995": round(thr_995, 6),
        "fpr_p99_single_sec": round(fpr_p99_1s, 4),
        "fpr_p99_2sec_streak": round(fpr_p99_2s, 4),
        "fpr_p995_2sec_streak": round(fpr_p995_2s, 4),
        "consecutive_alerts": 2,
    }
    (out_dir / "config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    pd.DataFrame(
        {
            "epoch": range(1, len(hist.history["loss"]) + 1),
            "train_loss": hist.history["loss"],
            "val_loss": hist.history["val_loss"],
        }
    ).to_csv(out_dir / "loss_history.csv", index=False)

    print(f"\nСохранено в {out_dir.resolve()}:")
    print("  scaler.pkl, autoencoder.keras, autoencoder.weights.h5, config.json, loss_history.csv")
    print(f"  Медиана MSE: {config['mse_median']:.6f}")
    print(f"  Порог p99  : {thr_99:.6f} (FPR 1с={fpr_p99_1s*100:.2f}%, 2с подряд={fpr_p99_2s*100:.2f}%)")
    print(f"  Порог p99.5: {thr_995:.6f} (FPR 2с подряд={fpr_p995_2s*100:.2f}%)")


if __name__ == "__main__":
    main()