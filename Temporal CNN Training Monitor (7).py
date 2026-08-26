#!/usr/bin/env python3
"""
Temporal CNN Training Monitor - v12/v13-style monolithic engine

Upgrades applied:
- GPU VRAM utilization monitoring (via nvidia-smi when available).
- Real dataset ingestion with pluggable loader/module and NPZ fallback.
- Multi-model training cycles via a model registry.
- TensorBoard integration for best and pruned models.
- Monolithic architecture: central TemporalTrainingEngine orchestrates all subsystems.
- Pruning is best-effort: if tfmot is incompatible, training continues without pruning.
- TFLite conversion is best-effort: if conversion fails, training still completes.

Original guarantees preserved:
- No runtime pip installs; clear dependency checks.
- Qt-safe background execution via QThread/QObject.
- 24/7 continuous mode with safe stop and automatic restart.
- Optuna-based hyperparameter search.
"""

import os
import sys
import time
import logging
import traceback
import importlib
import subprocess
from pathlib import Path

# ------------------------- dependency checks -------------------------

REQUIRED_MODULES = {
    "numpy": "numpy",
    "matplotlib": "matplotlib",
    "sklearn": "scikit-learn",
    "tensorflow": "tensorflow",
    "optuna": "optuna",
    "tensorflow_model_optimization": "tensorflow-model-optimization",
    "PyQt5": "PyQt5",
}

missing = []
for module_name, pip_name in REQUIRED_MODULES.items():
    try:
        importlib.import_module(module_name)
    except Exception:
        missing.append(pip_name)

if missing:
    print(
        "Missing or broken dependencies:\n  "
        + "\n  ".join(missing)
        + "\n\nInstall them with:\n"
        + f'"{sys.executable}" -m pip install ' + " ".join(missing),
        file=sys.stderr,
    )
    raise SystemExit(1)

# ------------------------------ imports ------------------------------

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
    log_loss,
    roc_auc_score,
)

import tensorflow as tf
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, TensorBoard
from tensorflow_model_optimization.sparsity import keras as sparsity
import optuna

from PyQt5 import QtWidgets, QtCore, QtGui

# --------------------------- configuration ---------------------------

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "training_output"
CHECKPOINT_DIR = OUTPUT_DIR / "checkpoints"
LOG_FILE = OUTPUT_DIR / "model_training.log"
TB_LOG_DIR = OUTPUT_DIR / "tensorboard"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
TB_LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
)

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
optuna.logging.set_verbosity(optuna.logging.WARNING)

# Core data / training defaults
DEFAULT_SEQ_LENGTH = 8
DEFAULT_SAMPLES = 256
DEFAULT_HEIGHT = 32
DEFAULT_WIDTH = 32
DEFAULT_CHANNELS = 3

OPTUNA_TRIALS = 3
TRIAL_EPOCHS = 3
FINAL_EPOCHS = 12
PRUNE_EPOCHS = 4
BATCH_SIZE = 8

# 24/7 service settings
CONTINUOUS_MODE = True
RESTART_DELAY_SECONDS = 30
MAX_CONSECUTIVE_FAILURES = 0  # 0 = keep retrying indefinitely

# Real dataset ingestion configuration
DATA_SOURCE_NPZ = os.environ.get("TEMPORAL_DATA_SOURCE", "").strip()
CUSTOM_LOADER_MODULE = os.environ.get("TEMPORAL_LOADER", "").strip()

# Multi-model registry configuration
DEFAULT_MODEL_KEY = "temporal_cnn_v1"
MODEL_KEYS_ENV = os.environ.get("TEMPORAL_MODEL_KEYS", "").strip()  # e.g. "temporal_cnn_v1,temporal_cnn_v2"

# GPU monitoring configuration
ENABLE_GPU_MONITORING = True
GPU_ABORT_THRESHOLD_MB = None  # e.g. 10000 to abort if any GPU used > 10GB


# ------------------------- TensorFlow startup ------------------------

def safe_tf_init():
    """Initialize GPU conservatively; always fall back to CPU."""
    try:
        gpus = tf.config.list_physical_devices("GPU")
        if gpus:
            initialized = []
            for gpu in gpus:
                try:
                    tf.config.experimental.set_memory_growth(gpu, True)
                    initialized.append(gpu.name)
                except RuntimeError as exc:
                    logging.warning("Could not set memory growth for %s: %s", gpu.name, exc)
            if initialized:
                logging.info("TensorFlow GPU mode: %s", initialized)
                return "GPU"
        logging.info("No usable GPU detected; using CPU.")
        return "CPU"
    except Exception:
        logging.exception("TensorFlow initialization failed; continuing in CPU mode.")
        try:
            tf.config.set_visible_devices([], "GPU")
        except Exception:
            pass
        return "CPU"


DEVICE_MODE = safe_tf_init()

logging.info(
    "Versions | TensorFlow=%s | tfmot=%s | Optuna=%s",
    getattr(tf, "__version__", "unknown"),
    getattr(sparsity, "__module__", "unknown"),
    getattr(optuna, "__version__", "unknown"),
)

# ------------------------- GPU memory monitoring ---------------------

def get_gpu_memory():
    """
    Query GPU memory usage via nvidia-smi.

    Returns a list of dicts: [{"used_mb": int, "total_mb": int}, ...]
    or [] if unavailable.
    """
    if not ENABLE_GPU_MONITORING:
        return []
    try:
        out = subprocess.check_output(
            [
                "nvidia-smi",
                "--query-gpu=memory.used,memory.total",
                "--format=csv,noheader,nounits",
            ],
            stderr=subprocess.DEVNULL,
        ).decode().strip().splitlines()
        usage = []
        for line in out:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 2:
                continue
            used, total = map(int, parts)
            usage.append({"used_mb": used, "total_mb": total})
        return usage
    except Exception:
        return []


def log_gpu_memory(tag=""):
    usage = get_gpu_memory()
    if not usage:
        logging.info("GPU memory (%s): unavailable or monitoring disabled", tag)
        return
    for idx, u in enumerate(usage):
        logging.info(
            "GPU %d memory (%s): %d / %d MB",
            idx, tag, u["used_mb"], u["total_mb"]
        )
    if GPU_ABORT_THRESHOLD_MB is not None:
        for u in usage:
            if u["used_mb"] >= GPU_ABORT_THRESHOLD_MB:
                raise RuntimeError(
                    f"GPU memory threshold exceeded ({u['used_mb']} MB >= {GPU_ABORT_THRESHOLD_MB} MB); "
                    "aborting training to protect system."
                )

# ------------------------------ data ---------------------------------

def load_demo_data(
    seq_length=DEFAULT_SEQ_LENGTH,
    num_samples=DEFAULT_SAMPLES,
    height=DEFAULT_HEIGHT,
    width=DEFAULT_WIDTH,
    channels=DEFAULT_CHANNELS,
):
    """
    Demo data generator retained from the original file.

    Replace this function with your real dataset loader when ready.
    """
    rng = np.random.default_rng(42)
    X_seq = rng.random(
        (num_samples, seq_length, height, width, channels),
        dtype=np.float32,
    )
    y_seq = rng.integers(0, 2, size=num_samples, dtype=np.int32).astype(np.float32)
    return X_seq, y_seq


def load_npz_data(path):
    """
    Load real dataset from NPZ file with keys: X_seq, y_seq.
    """
    data = np.load(path)
    X_seq = data["X_seq"].astype(np.float32)
    y_seq = data["y_seq"].astype(np.float32)
    return X_seq, y_seq


def load_custom_module_data(module_name):
    """
    Load data via a custom module that exposes load_and_preprocess_data().
    """
    mod = importlib.import_module(module_name)
    if not hasattr(mod, "load_and_preprocess_data"):
        raise AttributeError(
            f"Custom loader module '{module_name}' does not define load_and_preprocess_data()"
        )
    return mod.load_and_preprocess_data()


def load_and_preprocess_data(
    seq_length=DEFAULT_SEQ_LENGTH,
    num_samples=DEFAULT_SAMPLES,
    height=DEFAULT_HEIGHT,
    width=DEFAULT_WIDTH,
    channels=DEFAULT_CHANNELS,
):
    """
    Unified data loader:
    - If CUSTOM_LOADER_MODULE is set, use that.
    - Else if DATA_SOURCE_NPZ exists, load NPZ.
    - Else fall back to demo data.
    """
    if CUSTOM_LOADER_MODULE:
        logging.info("Using custom loader module: %s", CUSTOM_LOADER_MODULE)
        return load_custom_module_data(CUSTOM_LOADER_MODULE)

    if DATA_SOURCE_NPZ and Path(DATA_SOURCE_NPZ).exists():
        logging.info("Using NPZ dataset: %s", DATA_SOURCE_NPZ)
        return load_npz_data(DATA_SOURCE_NPZ)

    logging.info("Using demo random dataset (no real source configured).")
    return load_demo_data(seq_length, num_samples, height, width, channels)

# ----------------------------- plotting ------------------------------

def _safe_plot(fn, name):
    try:
        fn()
    except Exception:
        logging.exception("Could not create %s", name)


def plot_roc_curve(y_true, y_scores):
    def draw():
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        roc_auc_val = auc(fpr, tpr)
        plt.figure(figsize=(7, 5))
        plt.plot(fpr, tpr, lw=2, label=f"ROC AUC = {roc_auc_val:.3f}")
        plt.plot([0, 1], [0, 1], linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("Receiver Operating Characteristic")
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "roc_curve.png", dpi=150)
        plt.close()
    _safe_plot(draw, "ROC curve")


def plot_precision_recall_curve(y_true, y_scores):
    def draw():
        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        ap = average_precision_score(y_true, y_scores)
        plt.figure(figsize=(7, 5))
        plt.plot(recall, precision, label=f"Average Precision = {ap:.3f}")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall Curve")
        plt.legend(loc="lower left")
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "precision_recall_curve.png", dpi=150)
        plt.close()
    _safe_plot(draw, "precision-recall curve")

# ------------------------------- models ------------------------------

def build_temporal_cnn_v1(input_shape):
    """
    Valid for the default 8x32x32x3 temporal input.

    'same' padding avoids the shape-collapse crash caused by repeated
    valid Conv3D operations on short temporal sequences.
    """
    inputs = tf.keras.Input(shape=input_shape, name="temporal_input")
    x = tf.keras.layers.Conv3D(16, (3, 3, 3), padding="same", activation="relu")(inputs)
    x = tf.keras.layers.MaxPooling3D((1, 2, 2), padding="same")(x)
    x = tf.keras.layers.Conv3D(32, (3, 3, 3), padding="same", activation="relu")(x)
    x = tf.keras.layers.MaxPooling3D((2, 2, 2), padding="same")(x)
    x = tf.keras.layers.Conv3D(48, (3, 3, 3), padding="same", activation="relu")(x)
    x = tf.keras.layers.GlobalAveragePooling3D()(x)
    x = tf.keras.layers.Dense(64, activation="relu")(x)
    x = tf.keras.layers.Dropout(0.30)(x)
    outputs = tf.keras.layers.Dense(1, activation="sigmoid", name="prediction")(x)
    return tf.keras.Model(inputs, outputs, name="temporal_cnn_v1")


def build_temporal_cnn_v2(input_shape):
    """
    Slightly deeper variant to demonstrate multi-model cycles.
    """
    inputs = tf.keras.Input(shape=input_shape, name="temporal_input_v2")
    x = tf.keras.layers.Conv3D(24, (3, 3, 3), padding="same", activation="relu")(inputs)
    x = tf.keras.layers.MaxPooling3D((1, 2, 2), padding="same")(x)
    x = tf.keras.layers.Conv3D(36, (3, 3, 3), padding="same", activation="relu")(x)
    x = tf.keras.layers.MaxPooling3D((2, 2, 2), padding="same")(x)
    x = tf.keras.layers.Conv3D(64, (3, 3, 3), padding="same", activation="relu")(x)
    x = tf.keras.layers.GlobalAveragePooling3D()(x)
    x = tf.keras.layers.Dense(96, activation="relu")(x)
    x = tf.keras.layers.Dropout(0.35)(x)
    outputs = tf.keras.layers.Dense(1, activation="sigmoid", name="prediction_v2")(x)
    return tf.keras.Model(inputs, outputs, name="temporal_cnn_v2")


MODEL_BUILDERS = {
    "temporal_cnn_v1": build_temporal_cnn_v1,
    "temporal_cnn_v2": build_temporal_cnn_v2,
}


def get_model_cycle_keys():
    if MODEL_KEYS_ENV:
        keys = [k.strip() for k in MODEL_KEYS_ENV.split(",") if k.strip()]
        return [k for k in keys if k in MODEL_BUILDERS] or [DEFAULT_MODEL_KEY]
    return [DEFAULT_MODEL_KEY]


def compile_model(model, learning_rate):
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss=tf.keras.losses.BinaryCrossentropy(),
        metrics=["accuracy"],
    )

# ------------------------------ pruning ------------------------------

def apply_pruning(model, end_step):
    """
    Apply pruning to the complete Keras Functional model.

    If pruning fails due to tfmot / TensorFlow incompatibility,
    log the error and return the original model so the pipeline
    can continue without pruning.
    """
    end_step = max(1, int(end_step))
    pruning_params = {
        "pruning_schedule": sparsity.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.50,
            begin_step=0,
            end_step=end_step,
        )
    }

    try:
        pruned = sparsity.prune_low_magnitude(model, **pruning_params)
        return pruned
    except Exception as exc:
        logging.exception("Pruning failed; continuing without pruning: %s", exc)
        return model

# ----------------------------- evaluation ----------------------------

def evaluate_model(model, X_val, y_val, prefix="model"):
    y_scores = np.asarray(model.predict(X_val, verbose=0)).reshape(-1)
    y_scores = np.clip(y_scores, 1e-7, 1.0 - 1e-7)
    y_pred = (y_scores >= 0.5).astype(int)

    report = classification_report(
        y_val.astype(int),
        y_pred,
        labels=[0, 1],
        target_names=["Class 0", "Class 1"],
        zero_division=0,
    )
    matrix = confusion_matrix(y_val.astype(int), y_pred, labels=[0, 1])

    metrics = {
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "roc_auc": None,
        "pr_auc": None,
        "log_loss": float(log_loss(y_val, y_scores, labels=[0, 1])),
    }

    if len(np.unique(y_val)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_val, y_scores))
        metrics["pr_auc"] = float(average_precision_score(y_val, y_scores))
        plot_roc_curve(y_val, y_scores)
        plot_precision_recall_curve(y_val, y_scores)

    logging.info("%s evaluation: %s", prefix, metrics)
    logging.info("%s classification report:\n%s", prefix, report)
    return metrics

# --------------------------- TensorBoard -----------------------------

def make_tensorboard_callback(run_name):
    log_dir = TB_LOG_DIR / run_name
    log_dir.mkdir(parents=True, exist_ok=True)
    return TensorBoard(
        log_dir=str(log_dir),
        histogram_freq=1,
        write_graph=True,
        write_images=False,
    )

# --------------------------- training engine -------------------------

class StopRequested(Exception):
    pass


class TemporalTrainingEngine:
    """
    Monolithic orchestration engine for:
    - data loading
    - Optuna optimization
    - multi-model cycles
    - pruning (best-effort)
    - TensorBoard
    - TFLite export (best-effort)
    """

    def __init__(self):
        self.device_mode = DEVICE_MODE

    def run_cycle(self, progress_cb=None, stop_check_cb=None):
        """
        Run a full training cycle across all configured models.

        progress_cb: callable(str) for status messages.
        stop_check_cb: callable() that may raise StopRequested.
        """
        def emit(msg):
            logging.info(msg)
            if progress_cb:
                progress_cb(msg)

        def check_stop():
            if stop_check_cb:
                stop_check_cb()

        emit("Initializing TensorFlow training pipeline...")
        check_stop()

        emit("Loading and preprocessing dataset...")
        X_seq, y_seq = load_and_preprocess_data()
        split_idx = int(0.8 * len(X_seq))
        X_train, X_val = X_seq[:split_idx], X_seq[split_idx:]
        y_train, y_val = y_seq[:split_idx], y_seq[split_idx:]

        if len(X_train) == 0 or len(X_val) == 0:
            raise ValueError("Dataset split produced an empty training or validation set.")

        input_shape = tuple(X_train.shape[1:])
        emit(
            f"Data ready: train={len(X_train)}, validation={len(X_val)}, "
            f"input={input_shape}"
        )

        if ENABLE_GPU_MONITORING:
            emit("Checking GPU memory before training...")
            log_gpu_memory("pre-training")

        check_stop()
        model_keys = get_model_cycle_keys()
        emit(f"Running multi-model cycle: {model_keys}")

        all_results = {}

        for model_key in model_keys:
            check_stop()
            emit(f"Starting model variant: {model_key}")
            builder = MODEL_BUILDERS[model_key]

            emit(f"Running {OPTUNA_TRIALS} Optuna trials for {model_key}...")

            def objective(trial):
                check_stop()
                tf.keras.backend.clear_session()
                learning_rate = trial.suggest_float(
                    "learning_rate", 1e-4, 3e-3, log=True
                )
                model = builder(input_shape)
                compile_model(model, learning_rate)
                callbacks = [
                    EarlyStopping(
                        monitor="val_loss",
                        patience=1,
                        restore_best_weights=True,
                    ),
                    make_tensorboard_callback(f"{model_key}_optuna_trial_{trial.number}"),
                ]
                model.fit(
                    X_train, y_train,
                    batch_size=BATCH_SIZE,
                    epochs=TRIAL_EPOCHS,
                    validation_data=(X_val, y_val),
                    callbacks=callbacks,
                    verbose=0,
                )
                _, accuracy = model.evaluate(X_val, y_val, verbose=0)
                return float(accuracy)

            study = optuna.create_study(direction="maximize")
            study.optimize(
                objective,
                n_trials=OPTUNA_TRIALS,
                catch=(StopRequested,),
            )
            check_stop()

            completed_trials = [
                t for t in study.trials
                if t.state == optuna.trial.TrialState.COMPLETE and t.value is not None
            ]
            if not completed_trials:
                raise RuntimeError(f"No Optuna trial completed successfully for {model_key}.")

            best_trial = study.best_trial
            best_lr = float(best_trial.params["learning_rate"])
            emit(
                f"[{model_key}] Best learning rate: {best_lr:.6g}; "
                f"validation accuracy: {best_trial.value:.4f}"
            )

            tf.keras.backend.clear_session()
            emit(f"[{model_key}] Building and training best model...")
            best_model = builder(input_shape)
            compile_model(best_model, best_lr)

            checkpoint_file = CHECKPOINT_DIR / f"{model_key}_best_model.weights.h5"
            callbacks = [
                ModelCheckpoint(
                    filepath=str(checkpoint_file),
                    monitor="val_loss",
                    save_best_only=True,
                    save_weights_only=True,
                    verbose=0,
                ),
                EarlyStopping(
                    monitor="val_loss",
                    patience=3,
                    restore_best_weights=True,
                ),
                make_tensorboard_callback(f"{model_key}_best_model"),
            ]

            best_model.fit(
                X_train, y_train,
                batch_size=BATCH_SIZE,
                epochs=FINAL_EPOCHS,
                validation_data=(X_val, y_val),
                callbacks=callbacks,
                verbose=0,
            )
            check_stop()

            emit(f"[{model_key}] Evaluating best model...")
            metrics_best = evaluate_model(best_model, X_val, y_val, prefix=f"{model_key}_best_model")

            if ENABLE_GPU_MONITORING:
                emit(f"[{model_key}] Checking GPU memory after best model training...")
                log_gpu_memory(f"{model_key}_post-best-model")

            check_stop()
            emit(f"[{model_key}] Applying magnitude pruning (best-effort)...")
            steps_per_epoch = max(1, int(np.ceil(len(X_train) / BATCH_SIZE)))
            pruned_model = apply_pruning(
                best_model,
                end_step=steps_per_epoch * PRUNE_EPOCHS,
            )
            compile_model(pruned_model, best_lr)

            prune_callbacks = [
                sparsity.UpdatePruningStep(),
                EarlyStopping(
                    monitor="val_loss",
                    patience=2,
                    restore_best_weights=True,
                ),
                make_tensorboard_callback(f"{model_key}_pruned_model"),
            ]

            try:
                pruned_model.fit(
                    X_train, y_train,
                    batch_size=BATCH_SIZE,
                    epochs=PRUNE_EPOCHS,
                    validation_data=(X_val, y_val),
                    callbacks=prune_callbacks,
                    verbose=0,
                )
            except Exception as exc:
                logging.exception(
                    "[%s] Pruned model training failed; continuing with non-pruned model: %s",
                    model_key, exc
                )

            check_stop()

            emit(f"[{model_key}] Stripping pruning wrappers (best-effort) and saving models...")
            try:
                stripped_model = sparsity.strip_pruning(pruned_model)
            except Exception as exc:
                logging.exception(
                    "[%s] strip_pruning failed; using model as-is: %s",
                    model_key, exc
                )
                stripped_model = pruned_model

            compile_model(stripped_model, best_lr)

            keras_path = OUTPUT_DIR / f"{model_key}_pruned_model.keras"
            stripped_model.save(str(keras_path))

            emit(f"[{model_key}] Evaluating pruned/non-pruned final model...")
            metrics_pruned = evaluate_model(
                stripped_model, X_val, y_val, prefix=f"{model_key}_pruned_model"
            )

            if ENABLE_GPU_MONITORING:
                emit(f"[{model_key}] Checking GPU memory after pruned model training...")
                log_gpu_memory(f"{model_key}_post-pruned-model")

            check_stop()
            emit(f"[{model_key}] Converting model to quantized TFLite (best-effort)...")
            tflite_path = None
            try:
                converter = tf.lite.TFLiteConverter.from_keras_model(stripped_model)
                converter.optimizations = [tf.lite.Optimize.DEFAULT]
                tflite_model = converter.convert()

                tflite_path = OUTPUT_DIR / f"{model_key}_pruned_quantized_model.tflite"
                tflite_path.write_bytes(tflite_model)
                emit(f"[{model_key}] TFLite model saved: {tflite_path}")
            except Exception as exc:
                logging.exception(
                    "[%s] TFLite conversion failed; continuing without TFLite export: %s",
                    model_key, exc
                )
                emit(f"[{model_key}] TFLite conversion failed; no TFLite file generated.")

            all_results[model_key] = {
                "device": self.device_mode,
                "best_learning_rate": best_lr,
                "best_trial_accuracy": float(best_trial.value),
                "best_model_metrics": metrics_best,
                "pruned_model_metrics": metrics_pruned,
                "keras_model": str(keras_path),
                "tflite_model": str(tflite_path) if tflite_path is not None else None,
                "checkpoint_weights": str(checkpoint_file),
            }

            emit(f"[{model_key}] Model variant cycle completed.")

        emit("All model variants completed successfully.")
        return all_results

# --------------------------- training worker -------------------------

class TrainingWorker(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    error = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()
    completed = QtCore.pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._stop_requested = False
        self.engine = TemporalTrainingEngine()

    @QtCore.pyqtSlot()
    def request_stop(self):
        self._stop_requested = True
        self.progress.emit("Stop requested. The current operation will finish safely.")

    def _check_stop(self):
        if self._stop_requested:
            raise StopRequested()

    def _emit(self, message):
        logging.info(message)
        self.progress.emit(message)

    @QtCore.pyqtSlot()
    def run(self):
        try:
            def progress_cb(msg):
                self._emit(msg)

            def stop_check_cb():
                self._check_stop()

            results = self.engine.run_cycle(
                progress_cb=progress_cb,
                stop_check_cb=stop_check_cb,
            )

            self._emit("Training pipeline completed successfully.")
            self.completed.emit(results)

        except StopRequested:
            self._emit("Training stopped safely by user request.")
        except Exception as exc:
            details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            logging.error("Training pipeline failed:\n%s", details)
            self.error.emit(details)
        finally:
            self.finished.emit()

# ------------------------------- GUI ---------------------------------

class TrainingMonitor(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TensorFlow Temporal CNN Training Monitor")
        self.resize(980, 680)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        title = QtWidgets.QLabel("Temporal CNN Training Monitor")
        title.setFont(QtGui.QFont("Segoe UI", 16, QtGui.QFont.Bold))
        layout.addWidget(title)

        self.status_label = QtWidgets.QLabel("Status: Initializing...")
        self.status_label.setFont(QtGui.QFont("Segoe UI", 10))
        layout.addWidget(self.status_label)

        self.device_label = QtWidgets.QLabel(f"TensorFlow Device: {DEVICE_MODE}")
        layout.addWidget(self.device_label)

        controls = QtWidgets.QHBoxLayout()
        self.restart_button = QtWidgets.QPushButton("Restart Training")
        self.restart_button.clicked.connect(self.resume_service)
        controls.addWidget(self.restart_button)

        self.stop_button = QtWidgets.QPushButton("Stop Safely")
        self.stop_button.clicked.connect(self.stop_training)
        controls.addWidget(self.stop_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QtGui.QFont("Consolas", 9))
        self.log_view.setMaximumBlockCount(5000)
        layout.addWidget(self.log_view)

        self.thread = None
        self.worker = None
        self.running = False
        self.stop_requested = False
        self.consecutive_failures = 0
        self.restart_timer = QtCore.QTimer(self)
        self.restart_timer.setSingleShot(True)
        self.restart_timer.timeout.connect(self.start_training)

        QtCore.QTimer.singleShot(250, self.start_training)

    def start_training(self):
        if self.running:
            self.append_log("Training is already running.")
            return

        if self.stop_requested:
            self.append_log("24/7 service is stopped. Press Restart Training to resume.")
            return

        self.running = True
        self.restart_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText("Status: Starting automatically...")

        self.thread = QtCore.QThread(self)
        self.worker = TrainingWorker()
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.error.connect(self.on_error)
        self.worker.completed.connect(self.on_completed)
        self.worker.finished.connect(self.on_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def stop_training(self):
        self.stop_requested = True
        self.restart_timer.stop()
        if self.worker is not None and self.running:
            self.worker.request_stop()
            self.stop_button.setEnabled(False)
        else:
            self.status_label.setText("Status: 24/7 service stopped")

    def resume_service(self):
        if self.running:
            self.append_log("Training is already running.")
            return
        self.stop_requested = False
        self.consecutive_failures = 0
        self.append_log("24/7 service resumed.")
        self.start_training()

    def on_progress(self, message):
        self.status_label.setText(f"Status: {message}")
        self.append_log(message)

    def on_error(self, details):
        self.consecutive_failures += 1
        summary = details.strip().splitlines()[-1] if details.strip() else "Unknown error"
        self.status_label.setText(f"Status: ERROR - {summary}")
        self.append_log("ERROR:\n" + details)
        QtWidgets.QMessageBox.critical(
            self,
            "Training Error",
            "The training pipeline stopped with an error.\n\n"
            f"{summary}\n\nFull traceback was written to:\n{LOG_FILE}",
        )

    def on_completed(self, result):
        self.consecutive_failures = 0
        self.append_log("OUTPUTS:")
        for model_key, info in result.items():
            self.append_log(
                f"  [{model_key}] Keras model: {info['keras_model']}\n"
                f"  [{model_key}] TFLite model: {info['tflite_model']}\n"
                f"  [{model_key}] Checkpoint weights: {info['checkpoint_weights']}"
            )

    def on_finished(self):
        self.running = False
        self.worker = None
        self.thread = None
        self.restart_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        if self.stop_requested:
            self.status_label.setText("Status: 24/7 service stopped")
            self.append_log("Worker finished. Continuous service remains stopped.")
            return

        if CONTINUOUS_MODE:
            if MAX_CONSECUTIVE_FAILURES and self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self.status_label.setText("Status: Stopped after repeated failures")
                self.append_log("Maximum consecutive failures reached; automatic restart disabled.")
                return

            self.status_label.setText(
                f"Status: Restarting automatically in {RESTART_DELAY_SECONDS} seconds..."
            )
            self.append_log(
                f"Worker finished. 24/7 mode will restart training in "
                f"{RESTART_DELAY_SECONDS} seconds."
            )
            self.restart_timer.start(RESTART_DELAY_SECONDS * 1000)
        else:
            self.status_label.setText("Status: Idle (Finished)")
            self.append_log("Worker finished.")

    def append_log(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{timestamp}] {text}")

    def closeEvent(self, event):
        if self.running:
            answer = QtWidgets.QMessageBox.question(
                self,
                "Training Running",
                "The 24/7 service is still running. Request a safe stop and close after it finishes?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.Yes,
            )
            if answer == QtWidgets.QMessageBox.No:
                event.ignore()
                return
            self.stop_training()
            event.ignore()
            return
        event.accept()

# ------------------------------- main --------------------------------

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Temporal CNN Training Monitor")
    window = TrainingMonitor()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
