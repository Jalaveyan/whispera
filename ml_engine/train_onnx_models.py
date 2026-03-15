# -*- coding: utf-8 -*-
"""
Whispera ML Engine — обучение моделей + экспорт в ONNX.

Совместимо с Python 3.9+, TensorFlow не нужен.
Сохраняет .pkl (для переобучения) и .onnx (для инференса).

Установка:
    pip install scikit-learn numpy skl2onnx onnxruntime

Запуск:
    python ml_engine/train_onnx_models.py
"""

import os, sys, json, time
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
import numpy as np
from pathlib import Path

SCRIPT_DIR  = Path(__file__).resolve().parent
MODELS_DIR  = SCRIPT_DIR / "models"
FEATURE_DIM = 100

MODEL_PROFILES = {
    # MLPClassifier (нейронная сеть): hidden_layer_sizes — архитектура, max_iter — эпохи
    "light":    {"clf": dict(hidden_layer_sizes=(64, 32),     max_iter=300),
                 "dpi": dict(hidden_layer_sizes=(32, 16),     max_iter=300),
                 "ano": dict(hidden_layer_sizes=(32, 16),     max_iter=300),
                 "desc": "слабый ПК (1-2 ядра, <4 GB RAM)"},
    "standard": {"clf": dict(hidden_layer_sizes=(128, 64, 32), max_iter=600),
                 "dpi": dict(hidden_layer_sizes=(64, 32),     max_iter=600),
                 "ano": dict(hidden_layer_sizes=(64, 32),     max_iter=600),
                 "desc": "средний ПК (2-8 ядер, 2-12 GB RAM)"},
    "full":     {"clf": dict(hidden_layer_sizes=(256, 128, 64), max_iter=1000),
                 "dpi": dict(hidden_layer_sizes=(128, 64),    max_iter=1000),
                 "ano": dict(hidden_layer_sizes=(128, 64),    max_iter=1000),
                 "desc": "мощный ПК (8+ ядер, 12+ GB RAM, GPU)"},
}

TRAFFIC_CLASSES = {0: "encrypted_tls", 1: "http_plain", 2: "dns",
                   3: "vpn_tunnel",    4: "plaintext"}
DPI_CLASSES     = {0: "none", 1: "cleartext_inspection", 2: "fingerprint_risk"}
ANOMALY_CLASSES = {0: "normal", 1: "anomaly"}

# ── Transport selector ────────────────────────────────────────────────────────
# Вектор признаков (20 позиций) описывает состояние сети, а не байты пакета.
# Нейросеть учится: "в таких сетевых условиях → лучший транспорт".
#
#  Вектор сетевых условий (42 признака):
#  [0]  RTT к 8.8.8.8:53  / 2000 мс (1.0 = недоступен, 0.0 = мгновенно)
#  [1]  RTT к 1.1.1.1:443 / 2000 мс
#  [2]  RTT к google.com:443 / 2000 мс
#  [3]  RTT к целевому хосту / 2000 мс
#  [4]  доля доступных хостов (0.0–1.0)
#  [5]  1 если порт 443 доступен
#  [6]  1 если порт 80 доступен
#  [7]  средний RTT (нормализованный)
#  [8]  разброс RTT
#  ── success rate по каждому из 21 транспорта (prior=0.5) ──
#  [9]  udp            [10] tcp           [11] quic          [12] shadowsocks
#  [13] shadowtls      [14] obfs4         [15] websocket     [16] tuic
#  [17] mtproto        [18] meek          [19] domainfront   [20] yacloud
#  [21] yadisk         [22] vkwebrtc      [23] yatelemost    [24] okwebrtc
#  [25] snowflake      [26] vkbot         [27] tgbot         [28] torsocks
#  [29] vkwebrtc+phantom
#  ── метаданные ──
#  [30] consecutive_failures / 10 (ограничено 0–1)
#  [31] час суток / 24
#  ── средняя задержка 10 ключевых транспортов / 2000 мс ──
#  [32] udp    [33] tcp    [34] quic       [35] shadowsocks  [36] shadowtls
#  [37] meek   [38] vkwebrtc [39] yatelemost [40] vkbot      [41] tgbot

TS_FEATURE_DIM = 42

TRANSPORT_SELECTOR_CLASSES = {
    0:  "udp",
    1:  "tcp",
    2:  "quic",
    3:  "shadowsocks",
    4:  "shadowtls",
    5:  "obfs4",
    6:  "websocket",
    7:  "tuic",
    8:  "mtproto",
    9:  "meek",
    10: "domainfront",
    11: "yacloud",
    12: "yadisk",
    13: "vkwebrtc",
    14: "yatelemost",
    15: "okwebrtc",
    16: "snowflake",
    17: "vkbot",
    18: "tgbot",
    19: "torsocks",
    20: "vkwebrtc+phantom",
    # Комбо-транспорты (стекирование)
    21: "shadowsocks+meek",
    22: "shadowsocks+obfs4",
    23: "obfs4+meek",
    24: "shadowtls+meek",
}

# Профили нейросети для transport selector (42 фича, 21 класс)
TS_PROFILES = {
    "light":    dict(hidden_layer_sizes=(128, 64),          max_iter=500),
    "standard": dict(hidden_layer_sizes=(256, 128, 64),     max_iter=900),
    "full":     dict(hidden_layer_sizes=(512, 256, 128),    max_iter=1500),
}


# ── Извлечение признаков ──────────────────────────────────────────────────────
# ВАЖНО: эта функция идентична _build_features() в ml_api_server.py
# При любых изменениях — синхронизировать оба файла.
#
# Раскладка 100 позиций:
#  [0]     нормированная длина пакета (length / 1500)
#  [1]     среднее значение байт / 255
#  [2]     стд. отклонение байт / 255
#  [3]     энтропия Шеннона / 8
#  [4]     доля читаемых ASCII (0x20–0x7E)
#  [5]     доля нулевых байт (== 0x00)
#  [6]     доля высоких байт (> 200)
#  [7]     максимальная частота одного байта
#  [8]     доля управляющих символов (0x01–0x1F)
#  [9]     медиана байт / 255
#  [10]    количество уникальных байт / 256
#  [11]    частота переходов (консек. разных / n-1)  — высокая у шифрования
#  [12]    макс. серия одинаковых байт / min(n,500)  — высокая у паттернов/флуда
#  [13]    среднее |diff| консек. байт / 255          — низкое у простого текста
#  [14]    дисперсия 256-бин гистограммы × 1000       — высокая у неравномерных
#  [15]    асимметрия (skewness) / 5
#  [16-19] первые 4 байта пакета / 255 (magic bytes протокола)
#  [20]    1 если length > 500 (большой пакет → TLS/VPN), иначе 0
#  [21]    1 если 20 <= length <= 100 (маленький → DNS), иначе 0
#  [22]    1 если 100 < length <= 500 (средний → HTTP), иначе 0
#  [23]    среднее первых 20% байт / 255
#  [24]    среднее последних 20% байт / 255
#  [25-40] 16 грубых бинов: частоты групп байт [0..15], [16..31], ..., [240..255]
#  [41-72] тонкие бины гистограммы 26–57 (расширение [74-99] назад)
#  [73]    доля байт >= 128 (верхняя половина — характерна для шифрования)
#  [74-99] тонкие бины гистограммы 0–25

def build_features(data: bytes) -> np.ndarray:
    arr = np.array(list(data), dtype=np.float32)
    f   = np.zeros(FEATURE_DIM, dtype=np.float32)
    n   = len(arr)
    if n == 0:
        return f

    bc256 = np.bincount(arr.astype(int), minlength=256) / (n + 1e-10)

    f[0]  = n / 1500.0
    f[1]  = float(np.mean(arr)) / 255.0
    f[2]  = float(np.std(arr))  / 255.0
    f[3]  = float(-np.sum((bc256 + 1e-10) * np.log2(bc256 + 1e-10))) / 8.0
    f[4]  = float(np.sum((arr >= 32) & (arr <= 126))) / (n + 1e-10)
    f[5]  = float(np.sum(arr == 0))   / (n + 1e-10)
    f[6]  = float(np.sum(arr > 200))  / (n + 1e-10)
    f[7]  = float(np.max(bc256))
    f[8]  = float(np.sum((arr > 0) & (arr < 32))) / (n + 1e-10)
    f[9]  = float(np.median(arr)) / 255.0
    f[10] = len(np.unique(arr)) / 256.0

    if n > 1:
        f[11] = float(np.sum(arr[1:] != arr[:-1])) / (n - 1)
        f[13] = float(np.mean(np.abs(arr[1:] - arr[:-1]))) / 255.0

    # Макс. серия одинаковых байт
    cap = min(n, 500)
    max_run = cur = 1
    for i in range(1, cap):
        if arr[i] == arr[i - 1]:
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 1
    f[12] = max_run / cap

    f[14] = float(np.var(bc256)) * 1000.0
    std = float(np.std(arr))
    if std > 0:
        f[15] = float(np.mean(((arr - float(np.mean(arr))) / std) ** 3)) / 5.0

    # Первые 4 magic bytes
    for i in range(min(4, n)):
        f[16 + i] = arr[i] / 255.0

    # Размерные классы
    f[20] = 1.0 if n > 500         else 0.0
    f[21] = 1.0 if 20 <= n <= 100  else 0.0
    f[22] = 1.0 if 100 < n <= 500  else 0.0

    # Пространственные средние (начало / конец пакета)
    q = max(1, n // 5)
    f[23] = float(np.mean(arr[:q]))  / 255.0
    f[24] = float(np.mean(arr[-q:])) / 255.0

    # 16 грубых бинов (покрывают весь диапазон 0–255)
    for i in range(16):
        f[25 + i] = float(np.sum((arr >= i * 16) & (arr < (i + 1) * 16))) / (n + 1e-10)

    # Тонкие бины гистограммы 26–57
    for i in range(32):
        f[41 + i] = bc256[26 + i]

    f[73] = float(np.sum(arr >= 128)) / (n + 1e-10)

    # Тонкие бины гистограммы 0–25
    for i in range(26):
        f[74 + i] = bc256[i]

    return f


# ── Генераторы синтетических пакетов ─────────────────────────────────────────

def gen_encrypted_tls(n: int) -> np.ndarray:
    """TLS Application Data (0x17): большие пакеты, высокая энтропия.
    TLS Handshake (0x16): разного размера, первые байты 16 03 0x/01."""
    rng = np.random.default_rng()
    out = []
    for i in range(n):
        if i % 3 == 0:
            # TLS Handshake record: 0x16 0x03 0x01/0x03
            size    = rng.integers(100, 600)
            version = rng.choice([0x01, 0x03])
            header  = bytes([0x16, 0x03, version,
                             (size >> 8) & 0xFF, size & 0xFF])
            payload = bytes(rng.integers(0, 256, size=size, dtype=np.uint8))
            data    = header + payload
        else:
            # TLS Application Data: 0x17, крупный, почти случайный
            size   = rng.integers(300, 1400)
            header = bytes([0x17, 0x03, 0x03,
                           (size >> 8) & 0xFF, size & 0xFF])
            payload = bytes(rng.integers(0, 256, size=size, dtype=np.uint8))
            data    = header + payload
        out.append(build_features(data))
    return np.array(out, dtype=np.float32)


def gen_http_plain(n: int) -> np.ndarray:
    """HTTP/1.1: читаемый ASCII, заголовки + тело."""
    rng  = np.random.default_rng()
    methods  = [b"GET", b"POST", b"PUT", b"DELETE"]
    paths    = [b"/api/v1/data", b"/index.html", b"/login", b"/health"]
    out = []
    for _ in range(n):
        method = rng.choice(methods)
        path   = rng.choice(paths)
        hdr    = (method + b" " + path +
                  b" HTTP/1.1\r\nHost: example.com\r\n"
                  b"Accept: application/json\r\nContent-Type: text/plain\r\n\r\n")
        body   = bytes(rng.choice(range(32, 127), size=rng.integers(50, 400),
                                  replace=True).astype(np.uint8))
        out.append(build_features(hdr + body))
    return np.array(out, dtype=np.float32)


def gen_dns(n: int) -> np.ndarray:
    """DNS query/response: маленькие (20–80 байт), бинарная структура."""
    rng = np.random.default_rng()
    domains = [b"\x03www\x06google\x03com\x00",
               b"\x09cloudflare\x03com\x00",
               b"\x04mail\x05yahoo\x03com\x00"]
    out = []
    for i in range(n):
        txid    = rng.integers(0, 65536)
        flags   = 0x0100 if i % 2 == 0 else 0x8180   # query or response
        domain  = rng.choice(domains)
        header  = bytes([txid >> 8, txid & 0xFF,
                         flags >> 8, flags & 0xFF,
                         0x00, 0x01,   # qdcount
                         0x00, i % 2,  # ancount (0 or 1)
                         0x00, 0x00, 0x00, 0x00])
        footer  = bytes([0x00, 0x01,   # QTYPE A
                         0x00, 0x01])  # QCLASS IN
        data    = header + domain + footer
        out.append(build_features(data))
    return np.array(out, dtype=np.float32)


def gen_vpn_tunnel(n: int) -> np.ndarray:
    """Wireguard/IPSec-like: заголовок с высокими байтами + случайный payload."""
    rng = np.random.default_rng()
    out = []
    for i in range(n):
        size = int(rng.choice([512, 1024, 1280, 1400]))
        if i % 2 == 0:
            # Wireguard: type=4 (data), receiver index, counter, encrypted payload
            hdr = bytes([0x04, 0x00, 0x00, 0x00] +
                        list(rng.integers(0, 256, 4, dtype=np.uint8)) +  # receiver
                        list(rng.integers(0, 256, 8, dtype=np.uint8)))   # counter
        else:
            # IPSec ESP: SPI + seq
            hdr = bytes(rng.integers(128, 256, 8, dtype=np.uint8))
        payload = bytes(rng.integers(0, 256, size=size - len(hdr), dtype=np.uint8))
        out.append(build_features(hdr + payload))
    return np.array(out, dtype=np.float32)


def gen_plaintext(n: int) -> np.ndarray:
    """Открытый текст: низкая энтропия, только ASCII."""
    rng   = np.random.default_rng()
    chars = list(range(97, 123)) + [32, 32, 32, 10, 13, 9]
    out   = []
    for _ in range(n):
        size = rng.integers(100, 800)
        data = bytes(rng.choice(chars, size=size, replace=True).astype(np.uint8))
        out.append(build_features(data))
    return np.array(out, dtype=np.float32)


def gen_anomaly(n: int) -> np.ndarray:
    """Аномальный трафик: экстремальные паттерны."""
    rng = np.random.default_rng()
    out = []
    for i in range(n):
        k = i % 5
        if k == 0:
            data = bytes(rng.integers(0, 3, size=rng.integers(10, 50), dtype=np.uint8))
        elif k == 1:
            pat  = bytes([0xFF, 0x00] * 100)
            data = pat[:int(rng.integers(50, 200))]
        elif k == 2:
            data = bytes([0xFF] * int(rng.integers(1300, 1500)))
        elif k == 3:
            data = bytes(rng.integers(0, 32, size=rng.integers(20, 100), dtype=np.uint8))
        else:
            # Очень регулярный паттерн (сканирование портов)
            byte = int(rng.integers(0, 256))
            data = bytes([byte] * int(rng.integers(100, 400)))
        out.append(build_features(data))
    return np.array(out, dtype=np.float32)


# ── Экспорт в ONNX + сохранение .pkl ─────────────────────────────────────────

def export_model(model, base_path: str, label: str) -> None:
    """Сохраняет модель как .pkl (для переобучения) и .onnx (для инференса)."""
    import joblib
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    from sklearn.pipeline import Pipeline

    os.makedirs(os.path.dirname(base_path), exist_ok=True)

    # .pkl — нужен для warm_start переобучения
    joblib.dump(model, base_path + ".pkl")

    # .onnx — для быстрого инференса через onnxruntime
    opts = ({type(model.steps[-1][1]): {"zipmap": False}}
            if isinstance(model, Pipeline)
            else {type(model): {"zipmap": False}})
    onnx_m = convert_sklearn(
        model,
        initial_types=[("float_input", FloatTensorType([None, FEATURE_DIM]))],
        options=opts,
    )
    with open(base_path + ".onnx", "wb") as fh:
        fh.write(onnx_m.SerializeToString())

    kb_onnx = os.path.getsize(base_path + ".onnx") // 1024
    kb_pkl  = os.path.getsize(base_path + ".pkl")  // 1024
    print(f"    OK {label}  onnx={kb_onnx} KB  pkl={kb_pkl} KB")


# ── Обучение одного профиля ───────────────────────────────────────────────────

def train_profile(profile: str, X_clf, y_clf, X_dpi, y_dpi, X_ano, y_ano) -> None:
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    cfg    = MODEL_PROFILES[profile]
    suffix = "" if profile == "standard" else f"_{profile}"
    print(f"\n  [{profile}] {cfg['desc']}")

    def make_pipeline(params):
        return Pipeline([
            ("scaler", StandardScaler()),
            ("mlp", MLPClassifier(
                activation="relu", solver="adam",
                warm_start=True, random_state=42,
                **params
            )),
        ])

    # Traffic classifier
    clf = make_pipeline(cfg["clf"])
    clf.fit(X_clf, y_clf)
    acc = clf.score(X_clf, y_clf)
    export_model(clf, str(MODELS_DIR / "traffic_classifier" / f"rf_classifier{suffix}"),
                 f"traffic_classifier/rf_classifier{suffix}")
    (MODELS_DIR / "traffic_classifier").mkdir(parents=True, exist_ok=True)
    mlp_clf = clf.steps[-1][1]
    with open(MODELS_DIR / "traffic_classifier" / f"metadata{suffix}.json", "w") as fh:
        json.dump({"profile": profile, "model": "MLPClassifier",
                   "classes": TRAFFIC_CLASSES, "feature_dim": FEATURE_DIM,
                   "accuracy": round(acc, 4),
                   "hidden_layer_sizes": list(mlp_clf.hidden_layer_sizes),
                   "n_iter": mlp_clf.n_iter_,
                   "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S")},
                  fh, ensure_ascii=False, indent=2)

    # DPI detector
    dpi = make_pipeline(cfg["dpi"])
    dpi.fit(X_dpi, y_dpi)
    acc_dpi = dpi.score(X_dpi, y_dpi)
    export_model(dpi, str(MODELS_DIR / "dpi_detector" / f"dpi_detector{suffix}"),
                 f"dpi_detector/dpi_detector{suffix}")

    # Anomaly detector
    ano = make_pipeline(cfg["ano"])
    ano.fit(X_ano, y_ano)
    acc_ano = ano.score(X_ano, y_ano)
    export_model(ano, str(MODELS_DIR / "anomaly_detector" / f"isolation_forest{suffix}"),
                 f"anomaly_detector/isolation_forest{suffix}")

    print(f"    clf={acc:.3f}  dpi={acc_dpi:.3f}  ano={acc_ano:.3f}")


# ── Transport selector: генерация обучающих данных ────────────────────────────

def gen_transport_conditions(n_per_class: int = 500) -> tuple:
    """
    Генерирует синтетические сетевые условия для обучения transport selector.
    25 классов покрывают весь спектр транспортов: от свободной сети до
    экстремальной цензуры + 4 комбо-транспорта. Каждый класс имеет уникальный профиль SR/RTT.
    """
    rng = np.random.default_rng(42)

    def noise(val, scale=0.05, lo=0.0, hi=1.0):
        return float(np.clip(val + rng.normal(0, scale), lo, hi))

    def make_sample(
        # RTT + reachability (9 признаков)
        rtt8, rtt1, rttg, rttt, reach, p443, p80,
        # SR транспортов — порядок совпадает с TRANSPORT_SELECTOR_CLASSES (21 признак)
        sr_udp, sr_tcp, sr_quic, sr_ss, sr_stls, sr_o4, sr_ws, sr_tuic, sr_mtp,
        sr_meek, sr_df, sr_yac, sr_yad, sr_vk, sr_yat, sr_ok, sr_sf,
        sr_vkbot, sr_tgbot, sr_tors, sr_vkp,
        # метаданные (2 признака)
        consec_fail, hour,
        # задержки 10 ключевых транспортов (10 признаков)
        lat_udp, lat_tcp, lat_quic, lat_ss, lat_stls, lat_meek, lat_vk, lat_yat, lat_vkbot, lat_tgbot,
    ):
        """42-признаковый вектор с реалистичным шумом."""
        rtts = [v for v in [rtt8, rtt1, rttg, rttt] if v < 1.0]
        avg_rtt = float(np.mean(rtts)) if rtts else 1.0
        std_rtt = float(np.std(rtts))  if len(rtts) > 1 else 0.3
        n6 = lambda v: noise(v, 0.06, 0, 1)
        return [
            noise(rtt8,0.08), noise(rtt1,0.08), noise(rttg,0.08), noise(rttt,0.08),
            noise(reach,0.06,0,1), noise(p443,0.05,0,1), noise(p80,0.05,0,1),
            noise(avg_rtt,0.06), noise(std_rtt,0.05),
            # SR [9..29]
            n6(sr_udp), n6(sr_tcp), n6(sr_quic), n6(sr_ss),   n6(sr_stls),
            n6(sr_o4),  n6(sr_ws),  n6(sr_tuic),  n6(sr_mtp),  n6(sr_meek),
            n6(sr_df),  n6(sr_yac), n6(sr_yad),   n6(sr_vk),   n6(sr_yat),
            n6(sr_ok),  n6(sr_sf),  n6(sr_vkbot),  n6(sr_tgbot),n6(sr_tors),
            n6(sr_vkp),
            # метаданные [30..31]
            noise(min(consec_fail/10, 1.0), 0.04, 0, 1), noise(hour/24, 0.02, 0, 1),
            # задержки [32..41]
            noise(lat_udp,0.06),  noise(lat_tcp,0.06),  noise(lat_quic,0.06),
            noise(lat_ss,0.06),   noise(lat_stls,0.06), noise(lat_meek,0.06),
            noise(lat_vk,0.06),   noise(lat_yat,0.06),  noise(lat_vkbot,0.06),
            noise(lat_tgbot,0.06),
        ]

    X, y = [], []

    # ── Класс 0: udp ─────────────────────────────────────────────────────────
    # Полностью открытая сеть — UDP лучший выбор: минимальный overhead,
    # нет TLS handshake, максимальная скорость
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.02, rtt1=0.02, rttg=0.03, rttt=0.04,
            reach=0.99, p443=1.0, p80=1.0,
            sr_udp=0.96,sr_tcp=0.93,sr_quic=0.88,sr_ss=0.83,sr_stls=0.80,sr_o4=0.78,sr_ws=0.82,sr_tuic=0.80,sr_mtp=0.75,
            sr_meek=0.74,sr_df=0.72,sr_yac=0.76,sr_yad=0.73,sr_vk=0.70,sr_yat=0.69,sr_ok=0.70,sr_sf=0.65,
            sr_vkbot=0.66,sr_tgbot=0.68,sr_tors=0.55,sr_vkp=0.65,
            consec_fail=0, hour=rng.integers(0, 24),
            lat_udp=0.02,lat_tcp=0.03,lat_quic=0.03,lat_ss=0.06,lat_stls=0.06,lat_meek=0.12,
            lat_vk=0.08,lat_yat=0.09,lat_vkbot=0.20,lat_tgbot=0.18,
        ))
        y.append(0)

    # ── Класс 1: tcp ─────────────────────────────────────────────────────────
    # Свободная сеть, UDP частично заблокирован (firewall/NAT),
    # TCP работает надёжно
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.03, rtt1=0.02, rttg=0.04, rttt=0.05,
            reach=0.97, p443=1.0, p80=1.0,
            sr_udp=0.40,sr_tcp=0.94,sr_quic=0.78,sr_ss=0.83,sr_stls=0.80,sr_o4=0.78,sr_ws=0.82,sr_tuic=0.72,sr_mtp=0.75,
            sr_meek=0.74,sr_df=0.72,sr_yac=0.76,sr_yad=0.73,sr_vk=0.65,sr_yat=0.64,sr_ok=0.65,sr_sf=0.55,
            sr_vkbot=0.66,sr_tgbot=0.68,sr_tors=0.55,sr_vkp=0.62,
            consec_fail=0, hour=rng.integers(0, 24),
            lat_udp=0.08,lat_tcp=0.03,lat_quic=0.05,lat_ss=0.06,lat_stls=0.06,lat_meek=0.12,
            lat_vk=0.08,lat_yat=0.09,lat_vkbot=0.20,lat_tgbot=0.18,
        ))
        y.append(1)

    # ── Класс 2: quic ────────────────────────────────────────────────────────
    # TCP-level DPI throttles/resets TCP, UDP free but no raw UDP service —
    # QUIC (UDP 443) проходит нетронутым, лучше чем raw UDP
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.10, rtt1=0.12, rttg=0.14, rttt=0.15,
            reach=0.82, p443=0.90, p80=0.85,
            sr_udp=0.30,sr_tcp=0.38,sr_quic=0.90,sr_ss=0.70,sr_stls=0.68,sr_o4=0.65,sr_ws=0.60,sr_tuic=0.80,sr_mtp=0.55,
            sr_meek=0.58,sr_df=0.55,sr_yac=0.60,sr_yad=0.58,sr_vk=0.55,sr_yat=0.53,sr_ok=0.54,sr_sf=0.50,
            sr_vkbot=0.48,sr_tgbot=0.50,sr_tors=0.45,sr_vkp=0.52,
            consec_fail=2, hour=rng.integers(0, 24),
            lat_udp=0.25,lat_tcp=0.22,lat_quic=0.07,lat_ss=0.12,lat_stls=0.10,lat_meek=0.18,
            lat_vk=0.12,lat_yat=0.14,lat_vkbot=0.28,lat_tgbot=0.25,
        ))
        y.append(2)

    # ── Класс 3: shadowsocks ─────────────────────────────────────────────────
    # Payload DPI — инспекция содержимого пакетов, шифрование SS обходит
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.13, rtt1=0.16, rttg=0.18, rttt=0.20,
            reach=0.75, p443=0.88, p80=0.82,
            sr_udp=0.15,sr_tcp=0.30,sr_quic=0.60,sr_ss=0.89,sr_stls=0.82,sr_o4=0.80,sr_ws=0.65,sr_tuic=0.72,sr_mtp=0.60,
            sr_meek=0.68,sr_df=0.65,sr_yac=0.70,sr_yad=0.68,sr_vk=0.62,sr_yat=0.60,sr_ok=0.61,sr_sf=0.55,
            sr_vkbot=0.55,sr_tgbot=0.58,sr_tors=0.50,sr_vkp=0.60,
            consec_fail=2, hour=rng.integers(0, 24),
            lat_udp=0.30,lat_tcp=0.18,lat_quic=0.10,lat_ss=0.09,lat_stls=0.10,lat_meek=0.16,
            lat_vk=0.12,lat_yat=0.14,lat_vkbot=0.24,lat_tgbot=0.22,
        ))
        y.append(3)

    # ── Класс 4: shadowtls ───────────────────────────────────────────────────
    # TLS inspection DPI — SS идентифицирован по рукопожатию,
    # ShadowTLS маскирует трафик под легальный TLS handshake
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.14, rtt1=0.18, rttg=0.20, rttt=0.22,
            reach=0.70, p443=0.95, p80=0.60,
            sr_udp=0.10,sr_tcp=0.22,sr_quic=0.50,sr_ss=0.22,sr_stls=0.88,sr_o4=0.75,sr_ws=0.60,sr_tuic=0.68,sr_mtp=0.55,
            sr_meek=0.65,sr_df=0.62,sr_yac=0.66,sr_yad=0.63,sr_vk=0.58,sr_yat=0.56,sr_ok=0.57,sr_sf=0.52,
            sr_vkbot=0.50,sr_tgbot=0.52,sr_tors=0.48,sr_vkp=0.55,
            consec_fail=3, hour=rng.integers(0, 24),
            lat_udp=0.35,lat_tcp=0.20,lat_quic=0.12,lat_ss=0.18,lat_stls=0.10,lat_meek=0.16,
            lat_vk=0.12,lat_yat=0.14,lat_vkbot=0.26,lat_tgbot=0.24,
        ))
        y.append(4)

    # ── Класс 5: obfs4 ───────────────────────────────────────────────────────
    # Паттерновый DPI — сигнатуры SS и shadowTLS известны,
    # obfs4 рандомизирует весь трафик до неузнаваемости
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.16, rtt1=0.20, rttg=0.22, rttt=0.24,
            reach=0.65, p443=0.80, p80=0.70,
            sr_udp=0.08,sr_tcp=0.18,sr_quic=0.45,sr_ss=0.18,sr_stls=0.25,sr_o4=0.88,sr_ws=0.55,sr_tuic=0.62,sr_mtp=0.50,
            sr_meek=0.60,sr_df=0.58,sr_yac=0.62,sr_yad=0.60,sr_vk=0.55,sr_yat=0.53,sr_ok=0.54,sr_sf=0.50,
            sr_vkbot=0.48,sr_tgbot=0.50,sr_tors=0.46,sr_vkp=0.52,
            consec_fail=3, hour=rng.integers(0, 24),
            lat_udp=0.38,lat_tcp=0.22,lat_quic=0.14,lat_ss=0.20,lat_stls=0.18,lat_meek=0.18,
            lat_vk=0.14,lat_yat=0.16,lat_vkbot=0.28,lat_tgbot=0.26,
        ))
        y.append(5)

    # ── Класс 6: websocket ───────────────────────────────────────────────────
    # HTTP-level DPI — блокирует прямые соединения и шифрованные протоколы,
    # но разрешает WebSocket Upgrade (используется для CDN-доставки видео)
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.14, rtt1=0.17, rttg=0.19, rttt=0.21,
            reach=0.72, p443=0.95, p80=0.90,
            sr_udp=0.08,sr_tcp=0.22,sr_quic=0.38,sr_ss=0.25,sr_stls=0.30,sr_o4=0.35,sr_ws=0.88,sr_tuic=0.55,sr_mtp=0.50,
            sr_meek=0.62,sr_df=0.60,sr_yac=0.65,sr_yad=0.62,sr_vk=0.58,sr_yat=0.56,sr_ok=0.57,sr_sf=0.52,
            sr_vkbot=0.50,sr_tgbot=0.52,sr_tors=0.45,sr_vkp=0.55,
            consec_fail=3, hour=rng.integers(0, 24),
            lat_udp=0.35,lat_tcp=0.20,lat_quic=0.14,lat_ss=0.18,lat_stls=0.16,lat_meek=0.16,
            lat_vk=0.12,lat_yat=0.14,lat_vkbot=0.26,lat_tgbot=0.24,
        ))
        y.append(6)

    # ── Класс 7: tuic ────────────────────────────────────────────────────────
    # QUIC DPI (UDP 443 заблокирован), TUIC использует нестандартные порты
    # и собственную обфускацию поверх QUIC
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.15, rtt1=0.18, rttg=0.20, rttt=0.22,
            reach=0.68, p443=0.82, p80=0.72,
            sr_udp=0.07,sr_tcp=0.20,sr_quic=0.18,sr_ss=0.25,sr_stls=0.30,sr_o4=0.38,sr_ws=0.40,sr_tuic=0.88,sr_mtp=0.52,
            sr_meek=0.62,sr_df=0.60,sr_yac=0.64,sr_yad=0.61,sr_vk=0.56,sr_yat=0.54,sr_ok=0.55,sr_sf=0.50,
            sr_vkbot=0.48,sr_tgbot=0.50,sr_tors=0.46,sr_vkp=0.54,
            consec_fail=3, hour=rng.integers(0, 24),
            lat_udp=0.38,lat_tcp=0.21,lat_quic=0.20,lat_ss=0.18,lat_stls=0.16,lat_meek=0.17,
            lat_vk=0.13,lat_yat=0.15,lat_vkbot=0.27,lat_tgbot=0.25,
        ))
        y.append(7)

    # ── Класс 8: mtproto ─────────────────────────────────────────────────────
    # Telegram-specific blocking: стандартные протоколы режутся,
    # MTProto (нативный Telegram-протокол) не в списке сигнатур DPI
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.18, rtt1=0.22, rttg=0.25, rttt=0.28,
            reach=0.62, p443=0.85, p80=0.65,
            sr_udp=0.06,sr_tcp=0.18,sr_quic=0.30,sr_ss=0.20,sr_stls=0.22,sr_o4=0.28,sr_ws=0.32,sr_tuic=0.35,sr_mtp=0.87,
            sr_meek=0.60,sr_df=0.58,sr_yac=0.62,sr_yad=0.60,sr_vk=0.55,sr_yat=0.52,sr_ok=0.53,sr_sf=0.50,
            sr_vkbot=0.48,sr_tgbot=0.62,sr_tors=0.44,sr_vkp=0.52,
            consec_fail=4, hour=rng.integers(0, 24),
            lat_udp=0.40,lat_tcp=0.24,lat_quic=0.16,lat_ss=0.22,lat_stls=0.20,lat_meek=0.19,
            lat_vk=0.15,lat_yat=0.17,lat_vkbot=0.30,lat_tgbot=0.14,
        ))
        y.append(8)

    # ── Класс 9: meek ────────────────────────────────────────────────────────
    # Глубокий DPI — всё кроме TLS к известным CDN заблокировано,
    # Meek туннелирует через Azure CDN выглядя как легальный HTTPS
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.22, rtt1=0.28, rttg=0.30, rttt=0.35,
            reach=0.50, p443=0.92, p80=0.45,
            sr_udp=0.05,sr_tcp=0.12,sr_quic=0.15,sr_ss=0.16,sr_stls=0.18,sr_o4=0.20,sr_ws=0.22,sr_tuic=0.18,sr_mtp=0.25,
            sr_meek=0.88,sr_df=0.78,sr_yac=0.72,sr_yad=0.68,sr_vk=0.60,sr_yat=0.58,sr_ok=0.59,sr_sf=0.52,
            sr_vkbot=0.50,sr_tgbot=0.52,sr_tors=0.48,sr_vkp=0.58,
            consec_fail=4, hour=rng.integers(0, 24),
            lat_udp=0.50,lat_tcp=0.32,lat_quic=0.20,lat_ss=0.28,lat_stls=0.24,lat_meek=0.14,
            lat_vk=0.18,lat_yat=0.20,lat_vkbot=0.30,lat_tgbot=0.28,
        ))
        y.append(9)

    # ── Класс 10: domainfront ────────────────────────────────────────────────
    # Azure CDN (Meek) заблокирован, но generic domain fronting через
    # Cloudflare/другие CDN не в чёрном списке
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.21, rtt1=0.26, rttg=0.28, rttt=0.32,
            reach=0.52, p443=0.92, p80=0.44,
            sr_udp=0.05,sr_tcp=0.12,sr_quic=0.14,sr_ss=0.15,sr_stls=0.17,sr_o4=0.19,sr_ws=0.21,sr_tuic=0.17,sr_mtp=0.24,
            sr_meek=0.28,sr_df=0.88,sr_yac=0.74,sr_yad=0.70,sr_vk=0.62,sr_yat=0.60,sr_ok=0.61,sr_sf=0.54,
            sr_vkbot=0.52,sr_tgbot=0.54,sr_tors=0.50,sr_vkp=0.60,
            consec_fail=5, hour=rng.integers(0, 24),
            lat_udp=0.52,lat_tcp=0.30,lat_quic=0.19,lat_ss=0.26,lat_stls=0.22,lat_meek=0.22,
            lat_vk=0.17,lat_yat=0.19,lat_vkbot=0.29,lat_tgbot=0.27,
        ))
        y.append(10)

    # ── Класс 11: yacloud ────────────────────────────────────────────────────
    # Все западные CDN заблокированы (Azure, Cloudflare, Google CDN),
    # Яндекс.Облако — российский CDN, не в списке блокировок
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.20, rtt1=0.25, rttg=0.28, rttt=0.30,
            reach=0.55, p443=0.90, p80=0.42,
            sr_udp=0.05,sr_tcp=0.10,sr_quic=0.12,sr_ss=0.14,sr_stls=0.16,sr_o4=0.18,sr_ws=0.20,sr_tuic=0.16,sr_mtp=0.22,
            sr_meek=0.15,sr_df=0.18,sr_yac=0.88,sr_yad=0.80,sr_vk=0.68,sr_yat=0.65,sr_ok=0.66,sr_sf=0.55,
            sr_vkbot=0.55,sr_tgbot=0.58,sr_tors=0.50,sr_vkp=0.65,
            consec_fail=4, hour=rng.integers(0, 24),
            lat_udp=0.50,lat_tcp=0.28,lat_quic=0.18,lat_ss=0.24,lat_stls=0.20,lat_meek=0.22,
            lat_vk=0.15,lat_yat=0.13,lat_vkbot=0.27,lat_tgbot=0.25,
        ))
        y.append(11)

    # ── Класс 12: yadisk ─────────────────────────────────────────────────────
    # Яндекс.Облако тоже заблокировано (отдельные IP),
    # Яндекс.Диск (storage endpoint) работает через другой IP-range
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.22, rtt1=0.28, rttg=0.30, rttt=0.33,
            reach=0.50, p443=0.88, p80=0.40,
            sr_udp=0.04,sr_tcp=0.09,sr_quic=0.11,sr_ss=0.13,sr_stls=0.15,sr_o4=0.17,sr_ws=0.18,sr_tuic=0.14,sr_mtp=0.20,
            sr_meek=0.12,sr_df=0.14,sr_yac=0.22,sr_yad=0.88,sr_vk=0.68,sr_yat=0.65,sr_ok=0.64,sr_sf=0.55,
            sr_vkbot=0.52,sr_tgbot=0.55,sr_tors=0.48,sr_vkp=0.64,
            consec_fail=5, hour=rng.integers(0, 24),
            lat_udp=0.55,lat_tcp=0.30,lat_quic=0.20,lat_ss=0.26,lat_stls=0.22,lat_meek=0.24,
            lat_vk=0.16,lat_yat=0.14,lat_vkbot=0.28,lat_tgbot=0.26,
        ))
        y.append(12)

    # ── Класс 13: vkwebrtc ───────────────────────────────────────────────────
    # Жёсткая блокировка: CDN и обфускация не помогают,
    # только WebRTC через VK TURN relay проходит как легальный видеозвонок
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.65, rtt1=0.75, rttg=0.88, rttt=0.82,
            reach=0.22, p443=0.30, p80=0.25,
            sr_udp=0.03,sr_tcp=0.05,sr_quic=0.06,sr_ss=0.07,sr_stls=0.08,sr_o4=0.09,sr_ws=0.10,sr_tuic=0.08,sr_mtp=0.12,
            sr_meek=0.12,sr_df=0.11,sr_yac=0.14,sr_yad=0.13,sr_vk=0.86,sr_yat=0.70,sr_ok=0.72,sr_sf=0.60,
            sr_vkbot=0.55,sr_tgbot=0.48,sr_tors=0.42,sr_vkp=0.80,
            consec_fail=7, hour=rng.integers(0, 24),
            lat_udp=0.80,lat_tcp=0.75,lat_quic=0.68,lat_ss=0.72,lat_stls=0.70,lat_meek=0.58,
            lat_vk=0.20,lat_yat=0.24,lat_vkbot=0.35,lat_tgbot=0.45,
        ))
        y.append(13)

    # ── Класс 14: yatelemost ─────────────────────────────────────────────────
    # VK TURN заблокирован, Яндекс Телемост TURN работает
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.60, rtt1=0.72, rttg=0.85, rttt=0.80,
            reach=0.25, p443=0.32, p80=0.28,
            sr_udp=0.03,sr_tcp=0.04,sr_quic=0.05,sr_ss=0.06,sr_stls=0.07,sr_o4=0.08,sr_ws=0.09,sr_tuic=0.07,sr_mtp=0.11,
            sr_meek=0.11,sr_df=0.10,sr_yac=0.14,sr_yad=0.12,sr_vk=0.28,sr_yat=0.87,sr_ok=0.60,sr_sf=0.55,
            sr_vkbot=0.24,sr_tgbot=0.40,sr_tors=0.40,sr_vkp=0.26,
            consec_fail=7, hour=rng.integers(0, 24),
            lat_udp=0.78,lat_tcp=0.72,lat_quic=0.65,lat_ss=0.70,lat_stls=0.68,lat_meek=0.55,
            lat_vk=0.52,lat_yat=0.18,lat_vkbot=0.40,lat_tgbot=0.42,
        ))
        y.append(14)

    # ── Класс 15: okwebrtc ───────────────────────────────────────────────────
    # VK и Яндекс TURN заблокированы, OK.ru TURN доступен
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.62, rtt1=0.74, rttg=0.86, rttt=0.81,
            reach=0.22, p443=0.28, p80=0.24,
            sr_udp=0.03,sr_tcp=0.04,sr_quic=0.05,sr_ss=0.06,sr_stls=0.07,sr_o4=0.08,sr_ws=0.09,sr_tuic=0.07,sr_mtp=0.10,
            sr_meek=0.10,sr_df=0.09,sr_yac=0.12,sr_yad=0.11,sr_vk=0.22,sr_yat=0.28,sr_ok=0.87,sr_sf=0.54,
            sr_vkbot=0.20,sr_tgbot=0.38,sr_tors=0.38,sr_vkp=0.20,
            consec_fail=7, hour=rng.integers(0, 24),
            lat_udp=0.80,lat_tcp=0.74,lat_quic=0.67,lat_ss=0.71,lat_stls=0.69,lat_meek=0.56,
            lat_vk=0.54,lat_yat=0.50,lat_vkbot=0.42,lat_tgbot=0.44,
        ))
        y.append(15)

    # ── Класс 16: snowflake ──────────────────────────────────────────────────
    # Все известные TURN-серверы заблокированы по IP,
    # Tor Snowflake использует ephemeral WebRTC peers
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.68, rtt1=0.78, rttg=0.90, rttt=0.86,
            reach=0.18, p443=0.25, p80=0.20,
            sr_udp=0.03,sr_tcp=0.04,sr_quic=0.05,sr_ss=0.05,sr_stls=0.06,sr_o4=0.07,sr_ws=0.08,sr_tuic=0.06,sr_mtp=0.09,
            sr_meek=0.09,sr_df=0.08,sr_yac=0.10,sr_yad=0.09,sr_vk=0.12,sr_yat=0.14,sr_ok=0.15,sr_sf=0.84,
            sr_vkbot=0.18,sr_tgbot=0.22,sr_tors=0.55,sr_vkp=0.14,
            consec_fail=8, hour=rng.integers(0, 24),
            lat_udp=0.85,lat_tcp=0.80,lat_quic=0.72,lat_ss=0.78,lat_stls=0.76,lat_meek=0.65,
            lat_vk=0.62,lat_yat=0.60,lat_vkbot=0.50,lat_tgbot=0.52,
        ))
        y.append(16)

    # ── Класс 17: vkbot ──────────────────────────────────────────────────────
    # Все WebRTC заблокированы; VK Bot API работает через HTTP 443
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.75, rtt1=0.82, rttg=0.92, rttt=0.90,
            reach=0.12, p443=0.20, p80=0.15,
            sr_udp=0.02,sr_tcp=0.03,sr_quic=0.04,sr_ss=0.04,sr_stls=0.05,sr_o4=0.06,sr_ws=0.07,sr_tuic=0.05,sr_mtp=0.08,
            sr_meek=0.08,sr_df=0.07,sr_yac=0.09,sr_yad=0.08,sr_vk=0.18,sr_yat=0.16,sr_ok=0.17,sr_sf=0.12,
            sr_vkbot=0.86,sr_tgbot=0.62,sr_tors=0.45,sr_vkp=0.16,
            consec_fail=8, hour=rng.integers(0, 24),
            lat_udp=0.92,lat_tcp=0.88,lat_quic=0.80,lat_ss=0.85,lat_stls=0.83,lat_meek=0.72,
            lat_vk=0.65,lat_yat=0.62,lat_vkbot=0.28,lat_tgbot=0.40,
        ))
        y.append(17)

    # ── Класс 18: tgbot ──────────────────────────────────────────────────────
    # VK API заблокирован, Telegram Bot API работает
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.72, rtt1=0.80, rttg=0.90, rttt=0.88,
            reach=0.13, p443=0.22, p80=0.16,
            sr_udp=0.02,sr_tcp=0.03,sr_quic=0.04,sr_ss=0.04,sr_stls=0.05,sr_o4=0.06,sr_ws=0.07,sr_tuic=0.05,sr_mtp=0.10,
            sr_meek=0.08,sr_df=0.07,sr_yac=0.09,sr_yad=0.08,sr_vk=0.08,sr_yat=0.12,sr_ok=0.12,sr_sf=0.11,
            sr_vkbot=0.22,sr_tgbot=0.88,sr_tors=0.48,sr_vkp=0.10,
            consec_fail=8, hour=rng.integers(0, 24),
            lat_udp=0.90,lat_tcp=0.85,lat_quic=0.78,lat_ss=0.82,lat_stls=0.80,lat_meek=0.70,
            lat_vk=0.80,lat_yat=0.75,lat_vkbot=0.55,lat_tgbot=0.25,
        ))
        y.append(18)

    # ── Класс 19: torsocks ───────────────────────────────────────────────────
    # Почти всё заблокировано, Tor bridges — последний резерв
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.80, rtt1=0.85, rttg=0.93, rttt=0.92,
            reach=0.10, p443=0.18, p80=0.12,
            sr_udp=0.02,sr_tcp=0.02,sr_quic=0.03,sr_ss=0.04,sr_stls=0.05,sr_o4=0.06,sr_ws=0.06,sr_tuic=0.04,sr_mtp=0.07,
            sr_meek=0.07,sr_df=0.06,sr_yac=0.08,sr_yad=0.07,sr_vk=0.08,sr_yat=0.07,sr_ok=0.08,sr_sf=0.15,
            sr_vkbot=0.10,sr_tgbot=0.12,sr_tors=0.80,sr_vkp=0.08,
            consec_fail=9, hour=rng.integers(0, 24),
            lat_udp=0.95,lat_tcp=0.92,lat_quic=0.85,lat_ss=0.90,lat_stls=0.88,lat_meek=0.80,
            lat_vk=0.82,lat_yat=0.80,lat_vkbot=0.70,lat_tgbot=0.68,
        ))
        y.append(19)

    # ── Класс 20: vkwebrtc+phantom ───────────────────────────────────────────
    # Экстремальная цензура с анализом трафика
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.88, rtt1=0.91, rttg=0.95, rttt=0.94,
            reach=0.08, p443=0.14, p80=0.10,
            sr_udp=0.01,sr_tcp=0.02,sr_quic=0.02,sr_ss=0.03,sr_stls=0.03,sr_o4=0.04,sr_ws=0.04,sr_tuic=0.03,sr_mtp=0.05,
            sr_meek=0.05,sr_df=0.04,sr_yac=0.06,sr_yad=0.05,sr_vk=0.35,sr_yat=0.18,sr_ok=0.16,sr_sf=0.10,
            sr_vkbot=0.12,sr_tgbot=0.10,sr_tors=0.08,sr_vkp=0.88,
            consec_fail=9, hour=rng.integers(0, 24),
            lat_udp=0.98,lat_tcp=0.94,lat_quic=0.88,lat_ss=0.92,lat_stls=0.90,lat_meek=0.86,
            lat_vk=0.55,lat_yat=0.70,lat_vkbot=0.80,lat_tgbot=0.82,
        ))
        y.append(20)

    # ── Класс 21: shadowsocks+meek ────────────────────────────────────────────
    # DPI блокирует одиночный SS (видно по handshake) и одиночный Meek (по CDN IP),
    # но SS туннель поверх Meek CDN-трафика не детектируется
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.24, rtt1=0.30, rttg=0.32, rttt=0.36,
            reach=0.48, p443=0.90, p80=0.42,
            sr_udp=0.04,sr_tcp=0.10,sr_quic=0.12,sr_ss=0.15,sr_stls=0.16,sr_o4=0.18,sr_ws=0.20,sr_tuic=0.14,sr_mtp=0.22,
            sr_meek=0.30,sr_df=0.80,sr_yac=0.72,sr_yad=0.65,sr_vk=0.55,sr_yat=0.52,sr_ok=0.53,sr_sf=0.50,
            sr_vkbot=0.48,sr_tgbot=0.50,sr_tors=0.46,sr_vkp=0.55,
            consec_fail=5, hour=rng.integers(0, 24),
            lat_udp=0.55,lat_tcp=0.33,lat_quic=0.22,lat_ss=0.28,lat_stls=0.25,lat_meek=0.14,
            lat_vk=0.20,lat_yat=0.22,lat_vkbot=0.32,lat_tgbot=0.30,
        ))
        y.append(21)

    # ── Класс 22: shadowsocks+obfs4 ───────────────────────────────────────────
    # Паттерновый DPI + payload inspection: обфускация obfs4 скрывает SS трафик,
    # SS шифрует содержимое — оба слоя нужны одновременно
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.16, rtt1=0.20, rttg=0.22, rttt=0.25,
            reach=0.62, p443=0.78, p80=0.68,
            sr_udp=0.06,sr_tcp=0.16,sr_quic=0.42,sr_ss=0.18,sr_stls=0.24,sr_o4=0.22,sr_ws=0.48,sr_tuic=0.58,sr_mtp=0.45,
            sr_meek=0.55,sr_df=0.52,sr_yac=0.58,sr_yad=0.55,sr_vk=0.50,sr_yat=0.48,sr_ok=0.49,sr_sf=0.44,
            sr_vkbot=0.42,sr_tgbot=0.45,sr_tors=0.40,sr_vkp=0.50,
            consec_fail=4, hour=rng.integers(0, 24),
            lat_udp=0.40,lat_tcp=0.23,lat_quic=0.15,lat_ss=0.20,lat_stls=0.18,lat_meek=0.18,
            lat_vk=0.15,lat_yat=0.17,lat_vkbot=0.29,lat_tgbot=0.27,
        ))
        y.append(22)

    # ── Класс 23: obfs4+meek ──────────────────────────────────────────────────
    # Obfs4 блокируется по поведенческому анализу (несмотря на рандомизацию),
    # Meek CDN работает; obfs4 поверх meek обходит оба ограничения
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.23, rtt1=0.28, rttg=0.30, rttt=0.34,
            reach=0.49, p443=0.91, p80=0.43,
            sr_udp=0.04,sr_tcp=0.11,sr_quic=0.13,sr_ss=0.14,sr_stls=0.17,sr_o4=0.12,sr_ws=0.21,sr_tuic=0.15,sr_mtp=0.23,
            sr_meek=0.82,sr_df=0.25,sr_yac=0.70,sr_yad=0.62,sr_vk=0.52,sr_yat=0.50,sr_ok=0.51,sr_sf=0.48,
            sr_vkbot=0.46,sr_tgbot=0.48,sr_tors=0.44,sr_vkp=0.52,
            consec_fail=5, hour=rng.integers(0, 24),
            lat_udp=0.54,lat_tcp=0.32,lat_quic=0.21,lat_ss=0.27,lat_stls=0.24,lat_meek=0.13,
            lat_vk=0.19,lat_yat=0.21,lat_vkbot=0.31,lat_tgbot=0.29,
        ))
        y.append(23)

    # ── Класс 24: shadowtls+meek ──────────────────────────────────────────────
    # TLS inspection фильтрует ShadowTLS (распознаёт фейковый handshake);
    # туннелирование ShadowTLS поверх Meek CDN скрывает характерные паттерны
    for _ in range(n_per_class):
        X.append(make_sample(
            rtt8=0.22, rtt1=0.27, rttg=0.29, rttt=0.33,
            reach=0.50, p443=0.93, p80=0.44,
            sr_udp=0.04,sr_tcp=0.10,sr_quic=0.12,sr_ss=0.14,sr_stls=0.12,sr_o4=0.17,sr_ws=0.20,sr_tuic=0.14,sr_mtp=0.22,
            sr_meek=0.85,sr_df=0.22,sr_yac=0.68,sr_yad=0.60,sr_vk=0.50,sr_yat=0.48,sr_ok=0.49,sr_sf=0.46,
            sr_vkbot=0.44,sr_tgbot=0.46,sr_tors=0.42,sr_vkp=0.50,
            consec_fail=6, hour=rng.integers(0, 24),
            lat_udp=0.56,lat_tcp=0.34,lat_quic=0.22,lat_ss=0.29,lat_stls=0.26,lat_meek=0.13,
            lat_vk=0.20,lat_yat=0.22,lat_vkbot=0.32,lat_tgbot=0.30,
        ))
        y.append(24)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64)


def train_transport_selector(profile: str) -> None:
    """Обучает нейросеть выбора транспорта и сохраняет .onnx + .pkl."""
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    cfg    = TS_PROFILES[profile]
    suffix = "" if profile == "standard" else f"_{profile}"

    n_per = {"light": 300, "standard": 600, "full": 1000}[profile]
    X, y  = gen_transport_conditions(n_per_class=n_per)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("mlp", MLPClassifier(
            activation="relu", solver="adam",
            warm_start=True, random_state=42,
            **cfg,
        )),
    ])
    model.fit(X, y)
    acc = model.score(X, y)

    out_dir = MODELS_DIR / "transport_selector"
    out_dir.mkdir(parents=True, exist_ok=True)
    base = str(out_dir / f"transport_selector{suffix}")
    export_model_ts(model, base, f"transport_selector{suffix}")

    with open(out_dir / f"metadata{suffix}.json", "w") as fh:
        mlp = model.steps[-1][1]
        json.dump({
            "profile":      profile,
            "model":        "MLPClassifier",
            "classes":      TRANSPORT_SELECTOR_CLASSES,
            "feature_dim":  TS_FEATURE_DIM,
            "accuracy":     round(acc, 4),
            "n_iter":       mlp.n_iter_,
            "trained_at":   time.strftime("%Y-%m-%dT%H:%M:%S"),
        }, fh, ensure_ascii=False, indent=2)

    print(f"    transport_selector{suffix}  acc={acc:.3f}")


def export_model_ts(model, base_path: str, label: str) -> None:
    """Экспорт transport selector (TS_FEATURE_DIM входов)."""
    import joblib
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    from sklearn.pipeline import Pipeline

    os.makedirs(os.path.dirname(base_path), exist_ok=True)
    joblib.dump(model, base_path + ".pkl")

    opts = ({type(model.steps[-1][1]): {"zipmap": False}}
            if isinstance(model, Pipeline)
            else {type(model): {"zipmap": False}})
    onnx_m = convert_sklearn(
        model,
        initial_types=[("float_input", FloatTensorType([None, TS_FEATURE_DIM]))],
        options=opts,
    )
    with open(base_path + ".onnx", "wb") as fh:
        fh.write(onnx_m.SerializeToString())

    kb_onnx = os.path.getsize(base_path + ".onnx") // 1024
    kb_pkl  = os.path.getsize(base_path + ".pkl")  // 1024
    print(f"    OK {label}  onnx={kb_onnx} KB  pkl={kb_pkl} KB")


# ── Основной скрипт ───────────────────────────────────────────────────────────

def main():
    for pkg in ["sklearn", "skl2onnx", "joblib"]:
        try:
            __import__(pkg)
        except ImportError:
            print(f"ERROR: pip install {pkg}")
            sys.exit(1)

    N  = 300
    t0 = time.perf_counter()

    print("=" * 60)
    print("Whispera ML — обучение rf_classifier / dpi_detector / isolation_forest")
    print(f"Директория: {MODELS_DIR}")
    print("=" * 60)
    print("\nГенерация данных...")

    X_clf = np.vstack([gen_encrypted_tls(N), gen_http_plain(N),
                       gen_dns(N), gen_vpn_tunnel(N), gen_plaintext(N)])
    y_clf = np.array([0]*N + [1]*N + [2]*N + [3]*N + [4]*N, dtype=np.int64)

    X_dpi = np.vstack([
        np.vstack([gen_encrypted_tls(N//2), gen_dns(N//2)]),
        gen_plaintext(N),
        gen_http_plain(N),
    ])
    y_dpi = np.array([0]*N + [1]*N + [2]*N, dtype=np.int64)

    X_normal = np.vstack([gen_encrypted_tls(200), gen_http_plain(100), gen_dns(100)])
    X_ano    = np.vstack([X_normal, gen_anomaly(N)])
    y_ano    = np.array([0]*len(X_normal) + [1]*N, dtype=np.int64)

    print(f"  clf:{X_clf.shape} dpi:{X_dpi.shape} ano:{X_ano.shape}")
    print("\nОбучение:")

    for profile in ["light", "standard", "full"]:
        train_profile(profile, X_clf, y_clf, X_dpi, y_dpi, X_ano, y_ano)

    print("\nTransport selector (нейросеть выбора транспорта):")
    for profile in ["light", "standard", "full"]:
        train_transport_selector(profile)

    elapsed = time.perf_counter() - t0
    print(f"\nГотово за {elapsed:.1f}с")
    print("Файлы:")
    for p in sorted(MODELS_DIR.rglob("*.onnx")):
        print(f"  {p.relative_to(MODELS_DIR)}  ({p.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
