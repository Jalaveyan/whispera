# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for whispera-ml-server
# Build: pyinstaller whispera-ml-server.spec

import os
import sys
from pathlib import Path

# Repo root is 3 levels up from this spec file
REPO_ROOT = Path(SPECPATH).parent.parent.parent
ML_ENGINE  = str(REPO_ROOT / "ml_engine")

block_cipher = None

a = Analysis(
    [str(Path(SPECPATH) / "ml_api_server.py")],
    pathex=[SPECPATH, ML_ENGINE],
    binaries=[],
    datas=[
        # Bundle the trained models directory
        (str(REPO_ROOT / "ml_engine" / "models"), "ml_engine/models"),
    ],
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "fastapi",
        "pydantic",
        "sklearn",
        "sklearn.ensemble",
        "sklearn.svm",
        "sklearn.preprocessing",
        "sklearn.pipeline",
        "sklearn.neural_network",
        "numpy",
        "joblib",
        "skl2onnx",
        "skl2onnx.common.data_types",
        # ONNX Runtime (AMD/Intel GPU via DirectML, fallback CPU)
        "onnxruntime",
        "onnxruntime.capi",
        "onnxruntime.capi.onnxruntime_inference_collection",
        # TensorFlow / Keras (optional — used if installed alongside onnxruntime)
        "tensorflow",
        "tensorflow.keras",
        "tensorflow.keras.models",
        "tensorflow.keras.layers",
        "tensorflow.python.keras",
        "keras",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "seaborn", "jupyter", "IPython", "tkinter", "PyQt5"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="whispera-ml-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
