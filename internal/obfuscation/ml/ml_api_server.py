"""
Whispera ML API Server
Запускается рядом с клиентом whisp как whispera-ml-server.exe.

Предоставляет два слоя API:
  1. Серверная совместимость (/predict/traffic, /health, /models/*)
     — используется Go-кодом на сервере через PythonMLClient
  2. Клиентские API (/rank/bridges, /network/analyze, /recommend/transport)
     — используется whisp-клиентом для выбора мостов и транспорта
"""

import asyncio
import json
import logging
import math
import os
import secrets
import socket
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if getattr(sys, "frozen", False):
    _ML_ENGINE_DIR = os.path.join(sys._MEIPASS, "ml_engine")
else:
    _ML_ENGINE_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml_engine")
    )
_model_manager  = None
_ml_features_fn = None
_ml_backend     = "heuristic"
_hw_profile     = "standard"
_hw_info: dict  = {}



def _detect_hardware() -> dict:
    """
    Определяет ресурсы системы без внешних зависимостей.
    Возвращает dict с cpu_cores, ram_gb, has_gpu, gpu_vendor и profile.
    """
    cpu_cores = os.cpu_count() or 2
    ram_gb    = 4.0

    if sys.platform == "win32":
        try:
            import ctypes
            class _MEMSTATEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength",                ctypes.c_ulong),
                    ("dwMemoryLoad",             ctypes.c_ulong),
                    ("ullTotalPhys",             ctypes.c_ulonglong),
                    ("ullAvailPhys",             ctypes.c_ulonglong),
                    ("ullTotalPageFile",         ctypes.c_ulonglong),
                    ("ullAvailPageFile",         ctypes.c_ulonglong),
                    ("ullTotalVirtual",          ctypes.c_ulonglong),
                    ("ullAvailVirtual",          ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = _MEMSTATEX()
            stat.dwLength = ctypes.sizeof(stat)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            ram_gb = stat.ullTotalPhys / (1024 ** 3)
        except Exception:
            pass
    else:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        ram_gb = int(line.split()[1]) / (1024 * 1024)
                        break
        except Exception:
            pass

    has_gpu    = False
    gpu_vendor = "cpu"
    try:
        import onnxruntime as _ort
        _avail = set(_ort.get_available_providers())
        if "CUDAExecutionProvider" in _avail:
            has_gpu, gpu_vendor = True, "nvidia"
        elif "DmlExecutionProvider" in _avail:
            try:
                if sys.platform == "win32":
                    import subprocess
                    _out = subprocess.check_output(
                        ["wmic", "path", "win32_VideoController", "get", "name"],
                        timeout=3, stderr=subprocess.DEVNULL
                    ).decode(errors="ignore").lower()
                    if "nvidia" in _out:
                        gpu_vendor = "nvidia"
                    elif "amd" in _out or "radeon" in _out:
                        gpu_vendor = "amd"
                    else:
                        gpu_vendor = "intel"
                else:
                    gpu_vendor = "amd_or_intel"
            except Exception:
                gpu_vendor = "amd_or_intel"
            has_gpu = True
        elif "ROCMExecutionProvider" in _avail:
            has_gpu, gpu_vendor = True, "amd_rocm"
        elif "OpenVINOExecutionProvider" in _avail:
            has_gpu, gpu_vendor = True, "intel_openvino"
    except Exception:
        pass

    if cpu_cores <= 1 or ram_gb < 2.0:
        profile = "minimal"
    elif cpu_cores >= 8 and ram_gb >= 12.0:
        profile = "full"
    else:
        profile = "standard"

    env_override = os.environ.get("WHISPERA_ML_PROFILE", "").strip().lower()
    if env_override in ("minimal", "standard", "full"):
        profile = env_override

    return {
        "cpu_cores":  cpu_cores,
        "ram_gb":     round(ram_gb, 1),
        "has_gpu":    has_gpu,
        "gpu_vendor": gpu_vendor,
        "profile":    profile,
        "env_override": bool(env_override),
    }


def _build_features(data: bytes) -> "np.ndarray":
    """
    100-мерный вектор признаков пакета.
    СИНХРОНИЗИРОВАТЬ с build_features() в ml_engine/train_onnx_models.py.
    """
    import numpy as np
    arr = np.array(list(data), dtype=np.float32)
    f   = np.zeros(100, dtype=np.float32)
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

    for i in range(min(4, n)):
        f[16 + i] = arr[i] / 255.0

    f[20] = 1.0 if n > 500         else 0.0
    f[21] = 1.0 if 20 <= n <= 100  else 0.0
    f[22] = 1.0 if 100 < n <= 500  else 0.0

    q = max(1, n // 5)
    f[23] = float(np.mean(arr[:q]))  / 255.0
    f[24] = float(np.mean(arr[-q:])) / 255.0

    for i in range(16):
        f[25 + i] = float(np.sum((arr >= i * 16) & (arr < (i + 1) * 16))) / (n + 1e-10)

    for i in range(32):
        f[41 + i] = bc256[26 + i]

    f[73] = float(np.sum(arr >= 128)) / (n + 1e-10)

    for i in range(26):
        f[74 + i] = bc256[i]

    return f


class _OnnxModelManager:
    """
    ONNX inference layer с реальным самообучением.

    GPU: NVIDIA(CUDA) → AMD/Intel Windows(DirectML) → AMD Linux(ROCm)
         → Intel(OpenVINO) → CPU

    Профили моделей (suffix):
      minimal  → rf_classifier_light.onnx,  1 поток CPU
      standard → rf_classifier.onnx,        cpu//2 потоков
      full     → rf_classifier_full.onnx,   все потоки + GPU

    Самообучение (retrain_model):
      1. Загружает .pkl (sklearn) с диска
      2. warm_start: добавляет новые деревья, обрезает лишние
      3. Переобучает на replay_buffer
      4. Сохраняет .pkl (с ротацией бэкапа при < 85% диска)
      5. Экспортирует .onnx в то же место
      6. Горячая перезагрузка ONNX-сессии без перезапуска сервера
    """

    _MAX_ITER = {"minimal": 600,  "standard": 1200, "full": 2000}
    _ADD_ITER = {"minimal": 50,   "standard": 100,  "full": 200}

    def __init__(self, models_dir: str, hw: dict) -> None:
        import onnxruntime as ort
        import numpy as np
        self._np        = np
        self._ort       = ort
        self._models_dir = models_dir
        _log             = logging.getLogger("whispera-ml")
        profile          = hw.get("profile", "standard")
        cpu_cores        = hw.get("cpu_cores", os.cpu_count() or 2)
        self._hw_profile = profile
        self._lock       = threading.Lock()

        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        if profile == "minimal":
            so.intra_op_num_threads = 1
            so.inter_op_num_threads = 1
        elif profile == "standard":
            so.intra_op_num_threads = max(1, cpu_cores // 2)
            so.inter_op_num_threads = 1
        else:
            so.intra_op_num_threads = cpu_cores
            so.inter_op_num_threads = min(2, cpu_cores // 4)
        self._sess_opts = so

        available = set(ort.get_available_providers())
        if profile == "minimal":
            providers = ["CPUExecutionProvider"]
            _log.info("ONNX: minimal → CPU only")
        elif "CUDAExecutionProvider" in available:
            providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
            _log.info("ONNX: CUDA (NVIDIA)")
        elif "DmlExecutionProvider" in available:
            providers = ["DmlExecutionProvider", "CPUExecutionProvider"]
            _log.info("ONNX: DirectML (AMD/Intel GPU, Windows)")
        elif "ROCMExecutionProvider" in available:
            providers = ["ROCMExecutionProvider", "CPUExecutionProvider"]
            _log.info("ONNX: ROCm (AMD, Linux)")
        elif "OpenVINOExecutionProvider" in available:
            providers = ["OpenVINOExecutionProvider", "CPUExecutionProvider"]
            _log.info("ONNX: OpenVINO (Intel)")
        else:
            providers = ["CPUExecutionProvider"]
            _log.info("ONNX: CPU (%d threads)", so.intra_op_num_threads)
        self._providers = providers

        suffix = {"minimal": "_light", "standard": "", "full": "_full"}[profile]

        def _load_sess(base: str, subdir: str):
            for sfx in [suffix, ""]:
                p = os.path.join(models_dir, subdir, f"{base}{sfx}.onnx")
                if os.path.isfile(p):
                    _log.info("  loaded %s%s.onnx", base, sfx)
                    return ort.InferenceSession(p, sess_options=so, providers=providers), p
            return None, None

        self._clf,      self._clf_path = _load_sess("rf_classifier",    "traffic_classifier")
        self._dpi,      self._dpi_path = _load_sess("dpi_detector",     "dpi_detector")
        self._ano,      self._ano_path = _load_sess("isolation_forest",  "anomaly_detector")
        self._ts,       self._ts_path  = _load_sess("transport_selector","transport_selector")

        loaded = sum(1 for s in [self._clf, self._dpi, self._ano] if s)
        if loaded == 0:
            raise RuntimeError("No .onnx model files found")
        ts_status = "ok" if self._ts else "not found (will use heuristics)"
        _log.info("ONNX: %d/3 traffic models loaded, transport_selector=%s (profile=%s)",
                  loaded, ts_status, profile)


    def get_best_model(self, _task: str) -> str:
        return "onnx"

    def _run(self, session, features: "Any"):
        x   = features[:100].reshape(1, 100).astype(self._np.float32)
        out = session.run(None, {session.get_inputs()[0].name: x})
        return int(out[0][0]), (out[1][0] if len(out) > 1 else None)

    def predict_traffic(self, features: "Any", _model_type: str = "onnx"):
        if self._clf is None:
            raise ValueError("traffic classifier not loaded")
        cid, prob = self._run(self._clf, features)
        return cid, float(prob[cid]) if prob is not None else 0.85

    def detect_dpi(self, features: "Any"):
        if self._dpi is None:
            raise ValueError("dpi detector not loaded")
        dt, prob = self._run(self._dpi, features)
        conf = float(prob[dt]) if prob is not None else 0.80
        names = ["none", "cleartext_inspection", "fingerprint_risk",
                 "tls_fingerprint", "protocol_block", "deep_analysis"]
        return dt, conf, names[dt] if dt < len(names) else "unknown"

    def detect_anomaly(self, features: "Any", _method: str = "onnx"):
        if self._ano is None:
            raise ValueError("anomaly detector not loaded")
        lbl, prob = self._run(self._ano, features)
        score = float(prob[1]) if prob is not None else float(lbl)
        return lbl == 1, score


    _TS_CLASSES = {
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
        21: "shadowsocks+meek",
        22: "shadowsocks+obfs4",
        23: "obfs4+meek",
        24: "shadowtls+meek",
    }

    def predict_transport(self, net_features: "Any") -> tuple:
        """
        Предсказывает лучший транспорт по вектору сетевых условий (20 признаков).
        Возвращает (transport_name, confidence, {transport: prob}).
        """
        if self._ts is None:
            return None, 0.0, {}
        np = self._np
        x   = np.array(net_features[:42], dtype=np.float32).reshape(1, 42)
        out = self._ts.run(None, {self._ts.get_inputs()[0].name: x})
        cid  = int(out[0][0])
        prob = out[1][0] if len(out) > 1 else None
        conf = float(prob[cid]) if prob is not None else 0.7
        all_probs = {self._TS_CLASSES[i]: round(float(prob[i]), 3)
                     for i in range(len(self._TS_CLASSES))} if prob is not None else {}
        return self._TS_CLASSES.get(cid, "tcp"), conf, all_probs


    @staticmethod
    def _disk_usage_pct(path: str) -> float:
        import shutil
        d = shutil.disk_usage(os.path.dirname(os.path.abspath(path)))
        return d.used / d.total

    @staticmethod
    def _free_disk_backups(models_dir: str, warn_pct: float = 0.85) -> None:
        """Удаляет старые .bak файлы начиная с самых старых, пока диск < warn_pct."""
        from pathlib import Path
        baks = sorted(Path(models_dir).rglob("*.bak.*"),
                      key=lambda p: p.stat().st_mtime)
        for bak in baks:
            pct = _OnnxModelManager._disk_usage_pct(str(bak))
            if pct < warn_pct:
                break
            try:
                bak.unlink()
                log.info("Disk cleanup: removed %s (disk was %.0f%%)",
                         bak.name, pct * 100)
            except OSError:
                pass


    def retrain_model(self, model_name: str, X: "Any", y: "Any", **_kw) -> dict:
        """
        Переобучает модель на новых данных (replay buffer) и горячо
        перезагружает ONNX-сессию без перезапуска сервера.

        model_name: "traffic_classifier" | "dpi_detector" | "anomaly_detector"
        """
        import joblib, time as _time
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.neural_network import MLPClassifier
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        _MAP = {
            "traffic_classifier": ("_clf", self._clf_path),
            "dpi_detector":       ("_dpi", self._dpi_path),
            "anomaly_detector":   ("_ano", self._ano_path),
        }
        if model_name not in _MAP or _MAP[model_name][1] is None:
            raise ValueError(f"Unknown or unloaded model: {model_name}")

        attr, onnx_path = _MAP[model_name]
        pkl_path        = onnx_path.replace(".onnx", ".pkl")
        profile         = self._hw_profile
        max_iter        = self._MAX_ITER.get(profile, 600)
        add_iter        = self._ADD_ITER.get(profile, 100)

        if self._disk_usage_pct(onnx_path) > 0.95:
            log.warning("Disk >95%% full — skipping retrain of %s", model_name)
            return {"status": "skipped", "reason": "disk_full"}

        t0 = _time.perf_counter()

        with self._lock:
            if os.path.isfile(pkl_path):
                model = joblib.load(pkl_path)
                mlp = model.steps[-1][1] if isinstance(model, Pipeline) else model
                cur_iter = getattr(mlp, "max_iter", 300)
                new_iter = min(cur_iter + add_iter, max_iter)
                mlp.set_params(max_iter=new_iter, warm_start=True)
                log.info("Self-learning: warm_start %s max_iter %d->%d",
                         model_name, cur_iter, new_iter)
            else:
                _hidden = {"minimal": (64, 32), "standard": (128, 64, 32),
                           "full": (256, 128, 64)}.get(profile, (128, 64, 32))
                _iters  = {"minimal": 300, "standard": 600, "full": 1000}.get(profile, 600)
                model = Pipeline([
                    ("scaler", StandardScaler()),
                    ("mlp", MLPClassifier(
                        hidden_layer_sizes=_hidden, max_iter=_iters,
                        activation="relu", solver="adam",
                        warm_start=True, random_state=42,
                    )),
                ])
                log.info("Self-learning: creating new MLP %s layers=%s", model_name, _hidden)

            model.fit(X, y)
            acc = float(model.score(X, y))
            elapsed = _time.perf_counter() - t0

            disk_pct = self._disk_usage_pct(onnx_path)

            if disk_pct < 0.85:
                import time as _t
                ts   = int(_t.time())
                bak  = onnx_path + f".bak.{ts}"
                bak2 = pkl_path  + f".bak.{ts}"
                if os.path.isfile(onnx_path):
                    os.replace(onnx_path, bak)
                if os.path.isfile(pkl_path):
                    os.replace(pkl_path,  bak2)
                from pathlib import Path
                baks = sorted(
                    Path(os.path.dirname(onnx_path)).glob(
                        os.path.basename(onnx_path) + ".bak.*"
                    ),
                    key=lambda p: p.stat().st_mtime,
                )
                for old in baks[:-2]:
                    old.unlink(missing_ok=True)
            else:
                self._free_disk_backups(self._models_dir, warn_pct=0.85)
                log.warning("Disk %.0f%% — overwriting models in-place (no backup)",
                            disk_pct * 100)

            joblib.dump(model, pkl_path)

            opts = ({type(model.steps[-1][1]): {"zipmap": False}}
                    if isinstance(model, Pipeline)
                    else {type(model): {"zipmap": False}})
            onnx_m = convert_sklearn(
                model,
                initial_types=[("float_input", FloatTensorType([None, 100]))],
                options=opts,
            )
            with open(onnx_path, "wb") as fh:
                fh.write(onnx_m.SerializeToString())

            new_sess = self._ort.InferenceSession(
                onnx_path,
                sess_options=self._sess_opts,
                providers=self._providers,
            )
            setattr(self, attr, new_sess)

            mlp = model.steps[-1][1] if isinstance(model, Pipeline) else model
            n_iter_done = getattr(mlp, "n_iter_", getattr(mlp, "max_iter", 0))
            log.info(
                "Self-learning: %s retrained — acc=%.3f n_iter=%d elapsed=%.1fs disk=%.0f%%",
                model_name, acc, n_iter_done, elapsed, disk_pct * 100,
            )

        return {
            "status":   "ok",
            "model":    model_name,
            "accuracy": acc,
            "n_iter":   n_iter_done,
            "elapsed":  round(elapsed, 2),
            "disk_pct": round(disk_pct * 100, 1),
        }


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ML] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("whispera-ml")

_hw_info    = _detect_hardware()
_hw_profile = _hw_info["profile"]
log.info(
    "Hardware: %d CPU cores, %.1f GB RAM, GPU=%s (%s) → profile=%s",
    _hw_info["cpu_cores"], _hw_info["ram_gb"],
    _hw_info["gpu_vendor"], "yes" if _hw_info["has_gpu"] else "no",
    _hw_profile,
)

if os.path.isdir(_ML_ENGINE_DIR):
    sys.path.insert(0, _ML_ENGINE_DIR)

    _tf_err = None
    if _hw_profile == "minimal":
        log.info("Minimal profile: skipping TensorFlow to save RAM (~500 MB) — using ONNX Runtime")
        _tf_err = RuntimeError("skipped on minimal profile")
    else:
        try:
            import numpy as np
            from model_manager import ModelManager

            _model_manager  = ModelManager(os.path.join(_ML_ENGINE_DIR, "models"))
            _ml_features_fn = _build_features
            _ml_backend     = "tensorflow"
            log.info("ML backend: TensorFlow — loaded from %s", _ML_ENGINE_DIR)
        except Exception as _e:
            _tf_err = _e
            log.info("TensorFlow not available (%s) — trying ONNX Runtime", _e)

    if _tf_err is not None and _model_manager is None:

        try:
            import numpy as np
            _model_manager  = _OnnxModelManager(
                os.path.join(_ML_ENGINE_DIR, "models"), hw=_hw_info
            )
            _ml_features_fn = _build_features
            _ml_backend     = "onnx"
        except Exception as _onnx_err:
            log.warning("ONNX Runtime not available (%s) — using heuristics", _onnx_err)

_log_buffer: deque = deque(maxlen=500)

class _BufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        _log_buffer.append(self.format(record))

_buf_handler = _BufferHandler()
_buf_handler.setFormatter(logging.Formatter("%(asctime)s [ML] %(levelname)s %(message)s", datefmt="%H:%M:%S"))
logging.getLogger().addHandler(_buf_handler)

app = FastAPI(title="Whispera ML Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _bearer_auth(request: Request, call_next):
    """
    Проверяет API-токен для всех запросов кроме /health.
    Клиент должен посылать: Authorization: Bearer <token>
    Токен хранится в data/api_token и читается Go-клиентом из того же файла.
    """
    if _API_TOKEN and request.url.path not in ("/health", "/health/"):
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], _API_TOKEN)):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)



STARTUP_TIME = datetime.now().isoformat()
PREDICTIONS_TOTAL = 0
DPI_DETECTIONS = 0


RETRAIN_THRESHOLD = int(os.environ.get("WHISPERA_ML_RETRAIN_THRESHOLD", "500"))
RETRAIN_INTERVAL  = int(os.environ.get("WHISPERA_ML_RETRAIN_INTERVAL",  "300"))
PSEUDO_LABEL_MIN_CONFIDENCE = float(os.environ.get("WHISPERA_ML_PSEUDO_CONF", "0.85"))
REPLAY_BUFFER_SIZE = int(os.environ.get("WHISPERA_ML_REPLAY_SIZE", "2000"))

_replay_buffer: deque = deque(maxlen=REPLAY_BUFFER_SIZE)
_replay_lock   = threading.Lock()

_sl_stats = {
    "last_retrain":       None,
    "retrains_total":     0,
    "samples_collected":  0,
    "last_accuracy":      None,
    "status":             "idle",
}

_feedback_buffer: deque = deque(maxlen=5000)
_transport_stats: dict  = {}
_feedback_lock          = threading.Lock()


def _default_data_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "data")
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, "Whispera")

_DATA_DIR = os.environ.get("WHISPERA_ML_DATA_DIR", _default_data_dir())
_STATS_FILE = os.path.join(_DATA_DIR, "transport_stats.json")

def _load_transport_stats() -> None:
    """Загружает накопленную статистику транспортов из файла при старте."""
    global _transport_stats
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        if os.path.exists(_STATS_FILE):
            with open(_STATS_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                _transport_stats = loaded
                log.info("Transport stats loaded from %s (%d transports)",
                         _STATS_FILE, len(_transport_stats))
    except Exception as e:
        log.warning("Could not load transport stats: %s", e)

def _save_transport_stats() -> None:
    """Сохраняет статистику транспортов на диск (вызывается после каждого фидбека)."""
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        tmp = _STATS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_transport_stats, f, indent=2)
        os.replace(tmp, _STATS_FILE)
    except Exception as e:
        log.debug("Could not save transport stats: %s", e)

_load_transport_stats()


_TLS_DIR      = os.path.join(_DATA_DIR, "tls")
_TLS_CERT     = os.environ.get("WHISPERA_ML_TLS_CERT", os.path.join(_TLS_DIR, "ml_server.crt"))
_TLS_KEY      = os.environ.get("WHISPERA_ML_TLS_KEY",  os.path.join(_TLS_DIR, "ml_server.key"))
_TOKEN_FILE   = os.path.join(_DATA_DIR, "api_token")
_API_TOKEN: str  = ""
_USE_HTTPS: bool = False


def _ensure_self_signed_cert(cert_path: str, key_path: str) -> bool:
    """Генерирует самоподписанный ECDSA TLS-сертификат для localhost (pip install cryptography)."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True
    try:
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import timezone, timedelta

        priv_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "whispera-ml-localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(priv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(priv_key, hashes.SHA256())
        )
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(priv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info("Generated self-signed TLS cert → %s", cert_path)
        return True
    except ImportError:
        log.warning("'cryptography' not installed — HTTPS unavailable, falling back to HTTP")
        return False
    except Exception as exc:
        log.warning("TLS cert generation failed (%s) — falling back to HTTP", exc)
        return False


def _init_security() -> None:
    """Генерирует/загружает TLS-сертификат и API-токен. Вызывается один раз при старте."""
    global _API_TOKEN, _USE_HTTPS

    os.makedirs(_DATA_DIR, exist_ok=True)
    if os.path.exists(_TOKEN_FILE):
        try:
            _API_TOKEN = open(_TOKEN_FILE).read().strip()
            log.info("Loaded API token from %s", _TOKEN_FILE)
        except Exception as exc:
            log.warning("Could not read API token file: %s", exc)
    if not _API_TOKEN:
        _API_TOKEN = secrets.token_hex(32)
        try:
            with open(_TOKEN_FILE, "w") as f:
                f.write(_API_TOKEN)
            os.chmod(_TOKEN_FILE, 0o600)
            log.info("Generated new API token → %s", _TOKEN_FILE)
        except Exception as exc:
            log.warning("Could not save API token: %s — token is session-only", exc)

    if os.environ.get("WHISPERA_ML_HTTPS", "1") != "0":
        _USE_HTTPS = _ensure_self_signed_cert(_TLS_CERT, _TLS_KEY)


_init_security()


def _self_learning_loop() -> None:
    """Background thread: fine-tunes models when enough pseudo-labeled samples accumulate."""
    if _model_manager is None or _ml_features_fn is None:
        return

    import numpy as _np

    while True:
        time.sleep(RETRAIN_INTERVAL)

        with _replay_lock:
            buf_size = len(_replay_buffer)
            if buf_size < RETRAIN_THRESHOLD:
                continue
            try:
                samples = list(_replay_buffer)
                half  = buf_size // 2
                mixed = samples[:half] + samples[buf_size - half:]
                X = _np.array([s[0] for s in mixed], dtype=_np.float32)
                y = _np.array([s[1] for s in mixed], dtype=_np.int32)
            except Exception as e:
                log.warning("Self-learning: failed to prepare data — %s", e)
                continue

        try:
            _sl_stats["status"] = "retraining"
            log.info("Self-learning: fine-tuning on %d samples (backend=%s) …",
                     len(X), _ml_backend)

            if _ml_backend == "onnx":
                result = _model_manager.retrain_model("traffic_classifier", X, y)
            else:
                best_clf = _model_manager.get_best_model("traffic_classification")
                result = _model_manager.retrain_model(
                    "traffic_classifier", X, y,
                    model_type=best_clf,
                    epochs=2,
                    batch_size=32,
                )

            acc = result.get("accuracy") if isinstance(result, dict) else None
            _sl_stats["last_retrain"]   = datetime.now().isoformat()
            _sl_stats["retrains_total"] += 1
            _sl_stats["last_accuracy"]  = acc
            _sl_stats["status"]         = "idle"
            log.info("Self-learning: retrain done (acc=%.3f)", acc or 0)
        except Exception as e:
            _sl_stats["status"] = "error"
            log.warning("Self-learning: retrain failed — %s", e)


def _sl_add_sample(features: "Any", class_id: int, confidence: float) -> None:
    """Add a high-confidence prediction to the replay buffer."""
    if confidence < PSEUDO_LABEL_MIN_CONFIDENCE:
        return
    if _model_manager is None:
        return
    with _replay_lock:
        _replay_buffer.append((features, class_id))
        _sl_stats["samples_collected"] += 1


@app.on_event("startup")
async def on_startup():
    log.info("Whispera ML Server started — listening on http://127.0.0.1:8000")
    log.info("APIs: /health  /rank/bridges  /network/analyze  /recommend/transport  /predict/traffic")
    if _model_manager is not None:
        t = threading.Thread(target=_self_learning_loop, daemon=True, name="self-learning")
        t.start()
        log.info(
            "Self-learning enabled — threshold=%d samples, interval=%ds, min_conf=%.2f",
            RETRAIN_THRESHOLD, RETRAIN_INTERVAL, PSEUDO_LABEL_MIN_CONFIDENCE,
        )



@app.get("/health")
def health():
    return {
        "status": "ok",
        "model":   _ml_backend if _model_manager is not None else "heuristic_v1",
        "hw":      _hw_info,
        "started": STARTUP_TIME,
        "predictions_total": PREDICTIONS_TOTAL,
        "dpi_detections": DPI_DETECTIONS,
        "ml_engine": _model_manager is not None,
        "self_learning": {
            "enabled":          _model_manager is not None,
            "status":           _sl_stats["status"],
            "samples_collected": _sl_stats["samples_collected"],
            "replay_buffer":    len(_replay_buffer),
            "retrains_total":   _sl_stats["retrains_total"],
            "last_retrain":     _sl_stats["last_retrain"],
            "last_accuracy":    _sl_stats["last_accuracy"],
            "threshold":        RETRAIN_THRESHOLD,
            "interval_sec":     RETRAIN_INTERVAL,
        },
    }


@app.get("/logs")
def get_logs(n: int = 150):
    """Return up to n recent log lines (newest last)."""
    lines = list(_log_buffer)[-n:]
    return {"lines": lines, "total": len(_log_buffer)}


@app.get("/self-learning/status")
def sl_status():
    return {
        **_sl_stats,
        "replay_buffer":  len(_replay_buffer),
        "threshold":      RETRAIN_THRESHOLD,
        "interval_sec":   RETRAIN_INTERVAL,
        "min_confidence": PSEUDO_LABEL_MIN_CONFIDENCE,
    }


@app.get("/models/status")
def models_status():
    if _model_manager is not None:
        try:
            return _model_manager.get_model_status()
        except Exception:
            pass
    return {
        "traffic_classifier": {
            "model_name": "heuristic_v1",
            "is_trained": True,
            "accuracy": 0.87,
            "last_updated": STARTUP_TIME,
            "parameters": 0,
        },
        "dpi_detector": {
            "model_name": "entropy_heuristic",
            "is_trained": True,
            "accuracy": 0.82,
            "last_updated": STARTUP_TIME,
            "parameters": 0,
        },
    }


@app.post("/models/load")
def models_load():
    if _model_manager is not None:
        try:
            _model_manager.load_all_models()
            return {"status": "loaded", "models": "neural_network"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    return {"status": "loaded", "models": ["heuristic_v1", "entropy_heuristic"]}



class PacketData(BaseModel):
    data: List[float]
    protocol: str = "tcp"
    direction: str = "outbound"
    size: int = 0


class PredictionRequest(BaseModel):
    packets: List[PacketData]
    model_type: str = "cnn"
    task: str = "traffic_classification"


def _entropy(data: List[float]) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for v in data:
        key = int(v * 255)
        freq[key] = freq.get(key, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def _classify(packet: PacketData) -> Dict[str, Any]:
    global PREDICTIONS_TOTAL, DPI_DETECTIONS
    PREDICTIONS_TOTAL += 1

    data = packet.data
    size = packet.size or len(data)
    entropy = _entropy(data)
    proto = packet.protocol.lower()

    if _model_manager is not None and _ml_features_fn is not None:
        try:
            raw_bytes = bytes(int(v * 255) for v in data)
            features = _ml_features_fn(raw_bytes)

            best_clf = _model_manager.get_best_model("traffic_classification")
            class_id, confidence = _model_manager.predict_traffic(features, best_clf)

            dpi_type_r, dpi_conf, dpi_name_r = _model_manager.detect_dpi(features)

            best_ano = _model_manager.get_best_model("anomaly_detection")
            is_anomaly_r, anomaly_score_r = _model_manager.detect_anomaly(features, best_ano)

            if dpi_type_r > 0:
                DPI_DETECTIONS += 1

            _sl_add_sample(features, int(class_id), float(confidence))

            return {
                "class_id": int(class_id),
                "confidence": float(confidence),
                "protocol": packet.protocol,
                "direction": packet.direction,
                "dpi_type": int(dpi_type_r),
                "dpi_name": str(dpi_name_r),
                "is_anomaly": bool(is_anomaly_r),
                "anomaly_score": float(anomaly_score_r),
                "model": "neural_network",
            }
        except Exception as _e:
            log.debug("NN prediction failed, using heuristics: %s", _e)

    dpi_type = 0
    dpi_name = "none"
    is_anomaly = False
    anomaly_score = 0.0

    if entropy < 3.0 and size > 100:
        dpi_type = 1
        dpi_name = "cleartext_inspection"
        is_anomaly = True
        anomaly_score = 0.7
        DPI_DETECTIONS += 1
    elif 4.0 < entropy < 6.0 and "tls" not in proto:
        dpi_type = 2
        dpi_name = "fingerprint_risk"
        is_anomaly = True
        anomaly_score = 0.5
        DPI_DETECTIONS += 1

    if "tls" in proto or entropy > 7.0:
        class_id, confidence = 0, 0.92
    elif "http" in proto:
        class_id, confidence = 1, 0.88
    elif "dns" in proto:
        class_id, confidence = 2, 0.95
    elif entropy > 6.0:
        class_id, confidence = 3, 0.78
    else:
        class_id, confidence = 4, 0.65

    return {
        "class_id": class_id,
        "confidence": confidence,
        "protocol": packet.protocol,
        "direction": packet.direction,
        "dpi_type": dpi_type,
        "dpi_name": dpi_name,
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        "model": "heuristic",
    }


@app.post("/predict/traffic")
def predict_traffic(req: PredictionRequest):
    predictions = [_classify(p) for p in req.packets]
    avg_conf = sum(p["confidence"] for p in predictions) / max(len(predictions), 1)
    return {
        "predictions": predictions,
        "model_used": "heuristic_v1",
        "confidence": avg_conf,
        "timestamp": datetime.now().isoformat(),
    }



class BridgeInfo(BaseModel):
    id: str
    name: Optional[str] = None
    lat: float = 0.0
    lon: float = 0.0
    country: Optional[str] = None
    city: Optional[str] = None
    alive: bool = True
    latency_ms: Optional[float] = None
    load: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    cur_users: Optional[int] = None
    max_users: Optional[int] = None
    distance_km: Optional[float] = None
    type: Optional[str] = None


@app.post("/rank/bridges")
def rank_bridges(bridges: List[BridgeInfo]):
    """
    Ранжирует мосты по ML-скорингу.
    Учитывает: задержку, нагрузку, расстояние, заполненность, тип (white лучше).
    Возвращает список с добавленным полем ml_score (0–100) и ml_reason.
    """
    results = []
    for b in bridges:
        if not b.alive:
            results.append({**b.dict(), "ml_score": 0, "ml_reason": "offline"})
            continue

        score = 100.0
        reasons = []

        if b.latency_ms is not None:
            penalty = min(b.latency_ms / 10.0, 30)
            score -= penalty
            if b.latency_ms > 200:
                reasons.append("high latency")

        if b.load is not None:
            penalty = b.load * 0.25
            score -= penalty
            if b.load > 80:
                reasons.append("high load")

        if b.distance_km is not None:
            penalty = min(b.distance_km / 666.0, 15)
            score -= penalty

        if b.cur_users is not None and b.max_users:
            ratio = b.cur_users / b.max_users
            if ratio > 0.9:
                score -= 20
                reasons.append("nearly full")
            elif ratio > 0.7:
                score -= 10

        if b.type == "white":
            score += 8
            reasons.append("white bridge")

        if b.bandwidth_mbps and b.bandwidth_mbps > 100:
            score += 5

        score = max(0.0, min(100.0, score))
        ml_reason = ", ".join(reasons) if reasons else "optimal"

        results.append({
            **b.dict(),
            "ml_score": round(score, 1),
            "ml_reason": ml_reason,
        })

    results.sort(key=lambda x: x["ml_score"], reverse=True)
    log.info("Ranked %d bridges, top: %s (score %.1f)",
             len(results),
             results[0]["id"] if results else "—",
             results[0]["ml_score"] if results else 0)
    return results



class AnalyzeRequest(BaseModel):
    host: str = ""
    port: int = 443


async def _tcp_rtt(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    """Измеряет RTT через TCP-соединение."""
    try:
        loop = asyncio.get_event_loop()
        t0 = time.perf_counter()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        rtt = (time.perf_counter() - t0) * 1000
        writer.close()
        await writer.wait_closed()
        return round(rtt, 1)
    except Exception:
        return None


@app.post("/network/analyze")
async def network_analyze(req: AnalyzeRequest):
    """
    Анализирует сетевую среду пользователя:
    - Измеряет RTT к целевому хосту
    - Проверяет несколько хостов на доступность
    - Выдаёт вероятность DPI и рекомендуемый транспорт
    """
    probes = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 443),
        ("google.com", 443),
    ]
    if req.host:
        probes.insert(0, (req.host, req.port))

    results = {}
    tasks = {f"{h}:{p}": _tcp_rtt(h, p) for h, p in probes}
    for key, coro in tasks.items():
        results[key] = await coro

    reachable = sum(1 for v in results.values() if v is not None)
    total = len(results)
    rtts = [v for v in results.values() if v is not None]
    avg_rtt = round(sum(rtts) / len(rtts), 1) if rtts else None

    dpi_risk = "low"
    if reachable == 0:
        dpi_risk = "critical"
    elif reachable < total * 0.5:
        dpi_risk = "high"
    elif avg_rtt and avg_rtt > 300:
        dpi_risk = "medium"

    ml_transport  = None
    ml_confidence = 0.0
    if _model_manager is not None:
        try:
            with _feedback_lock:
                fb_stats = dict(_transport_stats)
            net_features = _build_network_features(results, fb_stats, 0)
            ml_transport, ml_confidence, _ = _model_manager.predict_transport(net_features)
        except Exception:
            ml_transport = None

    if ml_transport and ml_confidence >= 0.55:
        recommended_transport = ml_transport
        recommended_reason    = f"ML transport selector (conf={ml_confidence:.0%})"
    elif dpi_risk in ("critical", "high"):
        recommended_transport = "vkwebrtc"
        recommended_reason    = "Сильная блокировка — используем WebRTC (VK Video)"
    elif dpi_risk == "medium":
        recommended_transport = "meek"
        recommended_reason    = "Умеренный DPI — используем domain fronting (Meek)"
    else:
        recommended_transport = "tcp"
        recommended_reason    = "Сеть чистая — стандартный TCP с phantom/SNI"

    log.info("Network analysis: dpi_risk=%s transport=%s avg_rtt=%s (ml=%s conf=%.2f)",
             dpi_risk, recommended_transport, avg_rtt, ml_transport, ml_confidence)

    return {
        "probes": results,
        "reachable": reachable,
        "total_probed": total,
        "avg_rtt_ms": avg_rtt,
        "dpi_risk": dpi_risk,
        "recommended_transport": recommended_transport,
        "recommended_reason": recommended_reason,
        "timestamp": datetime.now().isoformat(),
    }



class TransportRequest(BaseModel):
    server_host: str = ""
    server_port: int = 8443
    latency_ms: Optional[float] = None
    dpi_risk: Optional[str] = None


TRANSPORT_PROFILES = {
    "low": {
        "transport": "tcp",
        "options": "phantom=1&sni=random_ru&asn=1&tls=chrome",
        "description": "TCP + Phantom + Chrome TLS fingerprint",
    },
    "medium": {
        "transport": "shadowsocks",
        "options": "method=chacha20-ietf-poly1305",
        "description": "Shadowsocks — хорошо против умеренного DPI",
    },
    "high": {
        "transport": "meek",
        "options": "fronting=azure",
        "description": "Meek domain fronting через Azure CDN",
    },
    "critical": {
        "transport": "vkwebrtc",
        "options": "ice_policy=relay&num_tracks=3",
        "description": "VK WebRTC — имитация видеозвонка ВКонтакте",
    },
}

_TS_TRANSPORT_OPTIONS = {
    "udp":              ("",                                              "Raw UDP — минимальный overhead, максимальная скорость"),
    "tcp":              ("phantom=1&sni=random_ru&asn=1&tls=chrome",    "TCP + Phantom + Chrome TLS fingerprint"),
    "quic":             ("alpn=h3",                                      "QUIC (HTTP/3) — обходит TCP-level DPI"),
    "shadowsocks":      ("method=chacha20-ietf-poly1305",               "Shadowsocks ChaCha20-Poly1305"),
    "shadowtls":        ("version=3&sni=cloudflare.com",                "ShadowTLS — маскировка под TLS handshake"),
    "obfs4":            ("iat-mode=0",                                   "Obfs4 — рандомизация паттернов трафика"),
    "websocket":        ("path=/ws&host=cdn.example.com",               "WebSocket Upgrade — HTTP/WS туннель"),
    "tuic":             ("alpn=h3&congestion=bbr",                      "TUIC — QUIC-based обфусцированный туннель"),
    "mtproto":          ("mode=fake-tls",                               "MTProto — Telegram-native протокол"),
    "meek":             ("fronting=azure",                               "Meek domain fronting (Azure CDN)"),
    "domainfront":      ("cdn=cloudflare",                              "Domain fronting через Cloudflare CDN"),
    "yacloud":          ("region=ru-central1",                          "Yandex Cloud CDN fronting"),
    "yadisk":           ("",                                             "Yandex Disk storage tunnel"),
    "vkwebrtc":         ("ice_policy=relay&num_tracks=3",               "VK WebRTC — имитация видеозвонка ВКонтакте"),
    "yatelemost":       ("ice_policy=relay",                            "Yandex Telemost WebRTC tunnel"),
    "okwebrtc":         ("ice_policy=relay",                            "OK.ru WebRTC — имитация звонка Одноклассники"),
    "snowflake":        ("broker=default",                              "Tor Snowflake — ephemeral WebRTC peers"),
    "vkbot":            ("mode=longpoll",                               "VK Bot API tunnel через ВКонтакте"),
    "tgbot":            ("mode=webhook",                                "Telegram Bot API tunnel"),
    "torsocks":         ("proxy=127.0.0.1:9050",                       "Tor SOCKS proxy — максимальная анонимность"),
    "vkwebrtc+phantom": ("ice_policy=relay&num_tracks=3&phantom=1",    "VK WebRTC + Phantom obfuscation"),
    "shadowsocks+meek": ("method=chacha20-ietf-poly1305&fronting=azure", "Shadowsocks поверх Meek CDN — двойная обфускация"),
    "shadowsocks+obfs4":("method=chacha20-ietf-poly1305&iat-mode=0",    "Shadowsocks + Obfs4 — шифрование + рандомизация"),
    "obfs4+meek":       ("iat-mode=0&fronting=azure",                    "Obfs4 поверх Meek CDN — рандомизация + CDN туннель"),
    "shadowtls+meek":   ("version=3&sni=cloudflare.com&fronting=azure",  "ShadowTLS поверх Meek CDN — TLS маскировка + CDN"),
}


def _build_network_features(
    probes: dict,
    feedback_stats: dict,
    consec_failures: int = 0,
) -> list:
    """
    Преобразует результаты network probe и историю фидбека в вектор из 42 признаков
    для transport selector нейросети (совпадает с gen_transport_conditions() в train_onnx_models.py).

    [0-3]   RTT к 8.8.8.8:53 / 1.1.1.1:443 / google.com:443 / target (ms/2000)
    [4-6]   reachability ratio, p443, p80
    [7-8]   avg_rtt, std_rtt
    [9-29]  SR для 21 транспорта (порядок совпадает с _TS_CLASSES):
            udp, tcp, quic, shadowsocks, shadowtls, obfs4, websocket, tuic, mtproto,
            meek, domainfront, yacloud, yadisk, vkwebrtc, yatelemost, okwebrtc,
            snowflake, vkbot, tgbot, torsocks, vkwebrtc+phantom
    [30]    consecutive_failures / 10
    [31]    hour / 24
    [32-41] avg latency: udp, tcp, quic, shadowsocks, shadowtls, meek,
                         vkwebrtc, yatelemost, vkbot, tgbot
    """
    _MAX_RTT_MS = 2000.0

    def _rtt(key: str) -> float:
        v = probes.get(key)
        return 1.0 if v is None else min(v / _MAX_RTT_MS, 1.0)

    def _sr(transport: str) -> float:
        s = feedback_stats.get(transport, {})
        total = s.get("success", 0) + s.get("fail", 0)
        return s.get("success", 0) / total if total > 0 else 0.5

    def _lat(transport: str) -> float:
        s = feedback_stats.get(transport, {})
        cnt = s.get("count", 0)
        if cnt == 0:
            return 0.5
        return min(s.get("total_latency", 0.0) / cnt / _MAX_RTT_MS, 1.0)

    rtt_8 = _rtt("8.8.8.8:53")
    rtt_1 = _rtt("1.1.1.1:443")
    rtt_g = _rtt("google.com:443")
    anchors = {"8.8.8.8:53", "1.1.1.1:443", "google.com:443"}
    target_key = next((k for k in probes if k not in anchors), None)
    rtt_t = _rtt(target_key) if target_key else 1.0

    vals = list(probes.values())
    reach_ratio = sum(1 for v in vals if v is not None) / len(vals) if vals else 0.0
    p443 = 1.0 if (probes.get("1.1.1.1:443") is not None or probes.get("google.com:443") is not None) else 0.0
    p80  = 0.5

    rtt_vals = [v for v in [rtt_8, rtt_1, rtt_g, rtt_t] if v < 1.0]
    avg_rtt  = sum(rtt_vals) / len(rtt_vals) if rtt_vals else 1.0
    std_rtt  = (sum((v - avg_rtt) ** 2 for v in rtt_vals) / len(rtt_vals)) ** 0.5 if len(rtt_vals) > 1 else 0.3

    return [
        rtt_8, rtt_1, rtt_g, rtt_t,
        reach_ratio, p443, p80,
        avg_rtt, std_rtt,
        _sr("udp"),        _sr("tcp"),        _sr("quic"),        _sr("shadowsocks"),
        _sr("shadowtls"),  _sr("obfs4"),      _sr("websocket"),   _sr("tuic"),
        _sr("mtproto"),    _sr("meek"),       _sr("domainfront"), _sr("yacloud"),
        _sr("yadisk"),     _sr("vkwebrtc"),   _sr("yatelemost"),  _sr("okwebrtc"),
        _sr("snowflake"),  _sr("vkbot"),      _sr("tgbot"),       _sr("torsocks"),
        _sr("vkwebrtc+phantom"),
        min(consec_failures / 10.0, 1.0),
        datetime.now().hour / 24.0,
        _lat("udp"),        _lat("tcp"),        _lat("quic"),        _lat("shadowsocks"),
        _lat("shadowtls"),  _lat("meek"),       _lat("vkwebrtc"),    _lat("yatelemost"),
        _lat("vkbot"),      _lat("tgbot"),
    ]


@app.post("/recommend/transport")
async def recommend_transport(req: TransportRequest):
    """
    Рекомендует транспорт через transport selector нейросеть.

    Алгоритм:
      1. Проводит TCP probe к целевому хосту + стандартным якорям.
      2. Собирает 42-признаковый вектор из probe-результатов + истории фидбека.
      3. Запускает transport selector MLP → transport + confidence.
      4. При confidence < 0.55 или недоступной модели — fallback на heuristic по DPI risk.
      5. Если выбранный транспорт стабильно не работает (<30% успеха) → upgrade.
    """
    probes: dict = {}
    if req.server_host:
        analysis = await network_analyze(AnalyzeRequest(host=req.server_host, port=req.server_port))
        probes   = analysis.get("probes", {})
        dpi_risk = analysis.get("dpi_risk", "low")
    else:
        dpi_risk = req.dpi_risk or "low"

    with _feedback_lock:
        fb_stats = dict(_transport_stats)

    consec = 0
    if probes:
        target_key = f"{req.server_host}:{req.server_port}"
        if probes.get(target_key) is None:
            consec = 3

    net_features = _build_network_features(probes, fb_stats, consec)

    transport_name = None
    confidence     = 0.0
    all_probs      = {}
    used_ml        = False

    if _model_manager is not None:
        try:
            transport_name, confidence, all_probs = _model_manager.predict_transport(net_features)
            used_ml = transport_name is not None
        except Exception as e:
            log.warning("Transport selector MLP error: %s — fallback to heuristic", e)

    if not used_ml or confidence < 0.55:
        risk    = req.dpi_risk or dpi_risk
        profile = TRANSPORT_PROFILES.get(risk, TRANSPORT_PROFILES["low"])
        transport_name = profile["transport"]
        log.info("Transport heuristic: dpi_risk=%s -> %s (ml_conf=%.2f)",
                 risk, transport_name, confidence)
    else:
        risk = dpi_risk

    _RISK_UPGRADE = {
        "udp":              "tcp",
        "tcp":              "quic",
        "quic":             "shadowsocks",
        "shadowsocks":      "shadowtls",
        "shadowtls":        "obfs4",
        "obfs4":            "websocket",
        "websocket":        "tuic",
        "tuic":             "mtproto",
        "mtproto":          "meek",
        "meek":             "domainfront",
        "domainfront":      "yacloud",
        "yacloud":          "yadisk",
        "yadisk":           "vkwebrtc",
        "vkwebrtc":         "yatelemost",
        "yatelemost":       "okwebrtc",
        "okwebrtc":         "snowflake",
        "snowflake":        "vkbot",
        "vkbot":            "tgbot",
        "tgbot":            "torsocks",
        "torsocks":         "vkwebrtc+phantom",
        "vkwebrtc+phantom": "shadowsocks+meek",
        "shadowsocks+meek": "shadowsocks+obfs4",
        "shadowsocks+obfs4":"obfs4+meek",
        "obfs4+meek":       "shadowtls+meek",
        "shadowtls+meek":   "shadowtls+meek",
    }
    with _feedback_lock:
        stats = _transport_stats.get(transport_name, {})
    total = stats.get("success", 0) + stats.get("fail", 0)
    upgraded = False
    if total >= 10:
        success_rate = stats.get("success", 0) / total
        if success_rate < 0.3 and transport_name in _RISK_UPGRADE:
            new_transport = _RISK_UPGRADE[transport_name]
            log.info(
                "Feedback override: %s success_rate=%.0f%% (<30%%) -> %s",
                transport_name, success_rate * 100, new_transport,
            )
            transport_name = new_transport
            upgraded = True

    opts, desc = _TS_TRANSPORT_OPTIONS.get(
        transport_name,
        _TS_TRANSPORT_OPTIONS.get("tcp"),
    )

    log.info(
        "Transport recommendation: host=%s dpi_risk=%s -> %s (ml=%s conf=%.2f upgraded=%s)",
        req.server_host, risk, transport_name, used_ml, confidence, upgraded,
    )

    return {
        "dpi_risk":    risk,
        "transport":   transport_name,
        "options":     opts,
        "description": desc,
        "confidence":  round(confidence, 3),
        "used_ml":     used_ml,
        "all_probs":   all_probs,
        "server":      f"{req.server_host}:{req.server_port}" if req.server_host else "",
    }



class ConnectionFeedback(BaseModel):
    transport:  str
    success:    bool
    latency_ms: Optional[float] = None
    dpi_risk:   Optional[str]   = None
    destination: str = ""


@app.post("/feedback/connection")
async def feedback_connection(fb: ConnectionFeedback):
    """
    Принимает результат реального соединения от Go Selector.Dial().
    Накапливает статистику для корректировки рекомендаций транспорта.
    """
    with _feedback_lock:
        _feedback_buffer.append({
            "transport":  fb.transport,
            "success":    fb.success,
            "latency_ms": fb.latency_ms,
            "dpi_risk":   fb.dpi_risk,
            "destination": fb.destination,
            "ts":         datetime.now().isoformat(),
        })
        stats = _transport_stats.setdefault(fb.transport, {
            "success": 0, "fail": 0, "total_latency": 0.0, "count": 0,
        })
        if fb.success:
            stats["success"] += 1
        else:
            stats["fail"] += 1
        if fb.latency_ms is not None:
            stats["total_latency"] += fb.latency_ms
            stats["count"] += 1
        _save_transport_stats()

    return {"status": "ok"}


@app.get("/feedback/stats")
def feedback_stats():
    """Статистика по транспортам на основе реальных соединений."""
    with _feedback_lock:
        result = {}
        for transport, stats in _transport_stats.items():
            total = stats["success"] + stats["fail"]
            result[transport] = {
                "success":      stats["success"],
                "fail":         stats["fail"],
                "total":        total,
                "success_rate": round(stats["success"] / total, 3) if total else None,
                "avg_latency_ms": round(stats["total_latency"] / stats["count"], 1)
                                  if stats["count"] else None,
            }
    return {
        "transports":      result,
        "feedback_buffer": len(_feedback_buffer),
    }



if __name__ == "__main__":
    port  = int(os.environ.get("WHISPERA_ML_PORT", "8000"))

    host  = os.environ.get("WHISPERA_ML_HOST", "127.0.0.1")

    proto = "https" if _USE_HTTPS else "http"
    log.info("Starting Whispera ML server on %s://%s:%d", proto, host, port)
    log.info("API token file: %s", _TOKEN_FILE)
    if host != "127.0.0.1":
        log.info("SERVER MODE: clients connect from outside — ensure firewall allows port %d", port)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        **({"ssl_certfile": _TLS_CERT, "ssl_keyfile": _TLS_KEY} if _USE_HTTPS else {}),
    )
