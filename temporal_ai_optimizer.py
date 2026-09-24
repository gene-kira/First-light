#!/usr/bin/env python3
"""
Universal Temporal AI Optimizer
Based on the original Temporal-ResNet program.

Goals
-----
1. Safely prepare/check the Python environment.
2. Detect available CPU/GPU acceleration.
3. Build a correct temporal Conv3D ResNet.
4. Create a real train/validation split.
5. Optimize learning rate/dropout with Optuna when available.
6. Use mixed precision only when supported.
7. Train and benchmark the model.
8. Attempt pruning/quantization only when compatible.
9. Save a JSON performance report and trained model.
10. Fail gracefully instead of crashing when optional libraries/features
    are unavailable.

IMPORTANT:
- The sample dataset is synthetic. Replace load_temporal_data() with your
  real video/sequence loader for meaningful training.
- This program does NOT overclock hardware or change Windows system settings.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_NAME = "Universal Temporal AI Optimizer"
APP_VERSION = "2.0"
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "temporal_optimizer_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE = OUTPUT_DIR / "temporal_resnet.keras"
OPTIMIZED_MODEL_FILE = OUTPUT_DIR / "temporal_resnet_optimized.keras"
REPORT_FILE = OUTPUT_DIR / "performance_report.json"
LOG_FILE = OUTPUT_DIR / "optimizer.log"

SEQ_LENGTH = 5
IMAGE_HEIGHT = 64
IMAGE_WIDTH = 64
CHANNELS = 3
NUM_CLASSES = 10

# Small defaults make first startup practical. Increase for real training.
SYNTHETIC_SAMPLES = 800
BATCH_SIZE = 16
TUNING_TRIALS = 5
TUNING_EPOCHS = 3
FINAL_EPOCHS = 15

REQUIRED_PACKAGES = {
    "numpy": "numpy>=1.24",
    "tensorflow": "tensorflow>=2.15",
}

OPTIONAL_PACKAGES = {
    "optuna": "optuna>=3.5",
    "tensorflow_model_optimization": "tensorflow-model-optimization>=0.8",
    "psutil": "psutil>=5.9",
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def section(title: str) -> None:
    log("")
    log("=" * 72)
    log(title)
    log("=" * 72)


# ---------------------------------------------------------------------------
# Dependency loader
# ---------------------------------------------------------------------------

def package_import_name(package: str) -> str:
    return {
        "tensorflow-model-optimization": "tensorflow_model_optimization",
    }.get(package, package)


def pip_install(spec: str) -> bool:
    """Install a package into the current Python environment."""
    log(f"[LIB] Installing: {spec}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", spec],
            stdout=subprocess.DEVNULL,
        )
        return True
    except Exception as exc:
        log(f"[LIB] Installation failed: {exc}")
        return False


def ensure_libraries() -> dict[str, bool]:
    """
    Check libraries and optionally install missing dependencies.

    Set TAI_AUTO_INSTALL=0 to disable automatic installation.
    """
    section("LIBRARY CHECK")

    auto_install = os.environ.get("TAI_AUTO_INSTALL", "1").lower() not in {
        "0", "false", "no"
    }

    status: dict[str, bool] = {}

    all_packages = {}
    all_packages.update(REQUIRED_PACKAGES)
    all_packages.update(OPTIONAL_PACKAGES)

    for package, spec in all_packages.items():
        module = package_import_name(package)
        try:
            importlib.import_module(module)
            status[package] = True
            log(f"[LIB] OK: {package}")
        except ImportError:
            if package in REQUIRED_PACKAGES and not auto_install:
                status[package] = False
                log(f"[LIB] MISSING REQUIRED: {package}")
            elif auto_install:
                status[package] = pip_install(spec)
                if status[package]:
                    try:
                        importlib.import_module(module)
                    except ImportError:
                        status[package] = False
            else:
                status[package] = False
                log(f"[LIB] Optional library unavailable: {package}")

    missing_required = [
        p for p in REQUIRED_PACKAGES if not status.get(p, False)
    ]
    if missing_required:
        raise RuntimeError(
            "Required libraries are missing: "
            + ", ".join(missing_required)
            + ". Run with TAI_AUTO_INSTALL=1 or install them manually."
        )

    return status


# ---------------------------------------------------------------------------
# Imports after dependency preparation
# ---------------------------------------------------------------------------

def load_runtime():
    import numpy as np
    import tensorflow as tf

    try:
        import optuna
    except ImportError:
        optuna = None

    try:
        import tensorflow_model_optimization as tfmot
    except ImportError:
        tfmot = None

    try:
        import psutil
    except ImportError:
        psutil = None

    return np, tf, optuna, tfmot, psutil


# ---------------------------------------------------------------------------
# Hardware detection
# ---------------------------------------------------------------------------

@dataclass
class HardwareInfo:
    system: str
    python: str
    tensorflow: str
    cpu_count: int
    gpu_count: int
    gpus: list[str]
    mixed_precision: bool


def detect_hardware(tf) -> HardwareInfo:
    section("HARDWARE DETECTION")

    gpus = tf.config.list_physical_devices("GPU")
    cpus = tf.config.list_physical_devices("CPU")

    gpu_names = []
    for gpu in gpus:
        gpu_names.append(str(gpu))

    for gpu in gpus:
        try:
            tf.config.experimental.set_memory_growth(gpu, True)
        except Exception as exc:
            log(f"[GPU] Memory-growth setup skipped: {exc}")

    mixed_precision_supported = bool(gpus)

    info = HardwareInfo(
        system=platform.platform(),
        python=platform.python_version(),
        tensorflow=tf.__version__,
        cpu_count=os.cpu_count() or 1,
        gpu_count=len(gpus),
        gpus=gpu_names,
        mixed_precision=mixed_precision_supported,
    )

    log(f"[HW] CPU threads: {info.cpu_count}")
    log(f"[HW] CPUs detected: {len(cpus)}")
    log(f"[HW] GPUs detected: {info.gpu_count}")

    if gpus:
        for index, gpu in enumerate(gpus):
            log(f"[HW] GPU {index}: {gpu}")
    else:
        log("[HW] No TensorFlow GPU detected; CPU mode will be used.")

    return info


def configure_precision(tf, hardware: HardwareInfo) -> None:
    try:
        from tensorflow.keras import mixed_precision

        if hardware.mixed_precision:
            mixed_precision.set_global_policy("mixed_float16")
            log("[PRECISION] mixed_float16 enabled")
        else:
            mixed_precision.set_global_policy("float32")
            log("[PRECISION] float32 selected")
    except Exception as exc:
        log(f"[PRECISION] Could not configure mixed precision: {exc}")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def residual_block(layers, x, filters: int, stride: int = 1,
                   dropout_rate: float = 0.0):
    """
    Correct Conv3D residual block.

    Input shape:
        (time, height, width, channels)

    Projection shortcut is used whenever spatial/temporal stride or channel
    count changes.
    """
    shortcut = x

    y = layers.Conv3D(
        filters,
        kernel_size=3,
        strides=stride,
        padding="same",
        use_bias=False,
    )(x)
    y = layers.BatchNormalization()(y)
    y = layers.Activation("relu")(y)

    if dropout_rate > 0:
        y = layers.SpatialDropout3D(dropout_rate)(y)

    y = layers.Conv3D(
        filters,
        kernel_size=3,
        strides=1,
        padding="same",
        use_bias=False,
    )(y)
    y = layers.BatchNormalization()(y)

    input_channels = x.shape[-1]
    if stride != 1 or input_channels != filters:
        shortcut = layers.Conv3D(
            filters,
            kernel_size=1,
            strides=stride,
            padding="same",
            use_bias=False,
        )(shortcut)
        shortcut = layers.BatchNormalization()(shortcut)

    y = layers.Add()([shortcut, y])
    y = layers.Activation("relu")(y)
    return y


def build_temporal_resnet(
    tf,
    input_shape: Tuple[int, int, int, int],
    num_classes: int = NUM_CLASSES,
    dropout_rate: float = 0.2,
):
    """
    Improved version of the original Temporal-ResNet.

    Correct input layout:
        (sequence, height, width, channels)
        e.g. (5, 64, 64, 3)
    """
    from tensorflow.keras import layers, Model

    inputs = layers.Input(shape=input_shape, name="temporal_input")

    x = layers.Conv3D(
        32,
        kernel_size=3,
        strides=1,
        padding="same",
        use_bias=False,
        name="stem_conv",
    )(inputs)
    x = layers.BatchNormalization(name="stem_bn")(x)
    x = layers.Activation("relu", name="stem_relu")(x)

    # Preserve more temporal information initially.
    x = residual_block(layers, x, 32, stride=1, dropout_rate=dropout_rate)

    x = residual_block(layers, x, 64, stride=2, dropout_rate=dropout_rate)
    x = residual_block(layers, x, 64, stride=1, dropout_rate=dropout_rate)

    x = residual_block(layers, x, 128, stride=2, dropout_rate=dropout_rate)
    x = residual_block(layers, x, 128, stride=1, dropout_rate=dropout_rate)

    x = layers.GlobalAveragePooling3D(name="global_average_pool")(x)
    x = layers.Dropout(dropout_rate, name="classifier_dropout")(x)

    # Keep output float32 when mixed precision is active.
    outputs = layers.Dense(
        num_classes,
        activation="softmax",
        dtype="float32",
        name="classification",
    )(x)

    return Model(inputs, outputs, name="TemporalResNet")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

def load_temporal_data(np, seq_length: int = SEQ_LENGTH,
                       num_samples: int = SYNTHETIC_SAMPLES,
                       height: int = IMAGE_HEIGHT,
                       width: int = IMAGE_WIDTH,
                       channels: int = CHANNELS,
                       num_classes: int = NUM_CLASSES):
    """
    Demonstration dataset.

    Replace this function with your real video/frame loader.

    The generated classes contain simple spatial/temporal patterns so the
    network has an actual learnable signal instead of pure random labels.
    """
    rng = np.random.default_rng(42)

    X = rng.normal(
        0.0, 0.05,
        size=(num_samples, seq_length, height, width, channels)
    ).astype("float32")

    y = rng.integers(0, num_classes, size=num_samples, dtype="int32")

    # Create a small class-dependent signal.
    for i in range(num_samples):
        cls = int(y[i])
        row = (cls * 5) % max(1, height - 8)
        col = (cls * 7) % max(1, width - 8)
        channel = cls % channels

        X[i, :, row:row + 8, col:col + 8, channel] += 0.8

        # Add a simple temporal trend.
        X[i, :, row:row + 3, col:col + 3, channel] += (
            np.linspace(0.0, 0.5, seq_length)[:, None, None]
        )

    X = np.clip(X, 0.0, 1.0)
    return X, y


def split_data(np, X, y, validation_fraction=0.2):
    from sklearn.model_selection import train_test_split

    return train_test_split(
        X,
        y,
        test_size=validation_fraction,
        random_state=42,
        stratify=y,
    )


class TemporalSequence:
    """
    Lightweight temporal augmentation sequence.

    Augmentations are applied to the whole sequence so frames remain
    temporally consistent.
    """

    def __init__(self, np, X, y, batch_size, training=True):
        self.np = np
        self.X = X
        self.y = y
        self.batch_size = batch_size
        self.training = training
        self.indices = np.arange(len(X))

    def __len__(self):
        return max(1, len(self.X) // self.batch_size)

    def on_epoch_end(self):
        if self.training:
            self.np.random.shuffle(self.indices)

    def __getitem__(self, index):
        start = index * self.batch_size
        end = min(start + self.batch_size, len(self.X))
        ids = self.indices[start:end]

        batch_x = self.X[ids].copy()
        batch_y = self.y[ids]

        if self.training:
            batch_x = self.augment(batch_x)

        return batch_x, batch_y

    def augment(self, batch):
        # Horizontal flip applied to every frame in a sequence.
        flip_mask = self.np.random.random(len(batch)) < 0.5
        batch[flip_mask] = batch[flip_mask, :, :, ::-1, :]

        # Small brightness variation shared across all frames.
        brightness = self.np.random.uniform(
            0.90, 1.10, size=(len(batch), 1, 1, 1, 1)
        ).astype("float32")
        batch *= brightness

        return self.np.clip(batch, 0.0, 1.0)


# ---------------------------------------------------------------------------
# Optimizer / compilation
# ---------------------------------------------------------------------------

def create_optimizer(tf, learning_rate: float):
    # Prefer the optimizer shipped with the installed Keras/TensorFlow.
    try:
        return tf.keras.optimizers.AdamW(
            learning_rate=learning_rate,
            weight_decay=1e-4,
            global_clipnorm=1.0,
        )
    except Exception:
        try:
            return tf.keras.optimizers.experimental.AdamW(
                learning_rate=learning_rate,
                weight_decay=1e-4,
                global_clipnorm=1.0,
            )
        except Exception:
            log("[OPTIMIZER] AdamW unavailable; falling back to Adam.")
            return tf.keras.optimizers.Adam(
                learning_rate=learning_rate,
                clipnorm=1.0,
            )


def compile_model(tf, model, learning_rate):
    optimizer = create_optimizer(tf, learning_rate)

    # Output is softmax, so from_logits must be False.
    loss = tf.keras.losses.SparseCategoricalCrossentropy(
        from_logits=False
    )

    model.compile(
        optimizer=optimizer,
        loss=loss,
        metrics=[
            tf.keras.metrics.SparseCategoricalAccuracy(name="accuracy")
        ],
    )
    return model


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark_model(model, X, y, batch_size=BATCH_SIZE) -> dict[str, float]:
    section("MODEL BENCHMARK")

    # Warm-up.
    warmup_count = min(batch_size, len(X))
    model.predict(X[:warmup_count], verbose=0)

    start = time.perf_counter()
    predictions = model.predict(X, batch_size=batch_size, verbose=0)
    elapsed = max(time.perf_counter() - start, 1e-9)

    accuracy = float(
        np.mean(np.argmax(predictions, axis=1) == y)
    )

    samples_per_second = len(X) / elapsed

    result = {
        "samples": int(len(X)),
        "elapsed_seconds": float(elapsed),
        "samples_per_second": float(samples_per_second),
        "accuracy": accuracy,
    }

    log(f"[BENCH] Inference time: {elapsed:.3f}s")
    log(f"[BENCH] Throughput: {samples_per_second:.2f} samples/sec")
    log(f"[BENCH] Accuracy: {accuracy:.4f}")

    return result


# ---------------------------------------------------------------------------
# Optuna tuning
# ---------------------------------------------------------------------------

def tune_hyperparameters(
    tf,
    np,
    optuna,
    X_train,
    y_train,
    X_val,
    y_val,
    input_shape,
    num_classes,
    trials=TUNING_TRIALS,
):
    if optuna is None:
        log("[OPTUNA] Not installed; using safe defaults.")
        return {
            "learning_rate": 3e-4,
            "dropout_rate": 0.15,
        }

    section("OPTUNA HYPERPARAMETER SEARCH")

    # Avoid nested GPU contention.
    def objective(trial):
        learning_rate = trial.suggest_float(
            "learning_rate",
            1e-5,
            1e-3,
            log=True,
        )
        dropout_rate = trial.suggest_float(
            "dropout_rate",
            0.0,
            0.4,
        )

        model = build_temporal_resnet(
            tf,
            input_shape,
            num_classes=num_classes,
            dropout_rate=dropout_rate,
        )
        compile_model(tf, model, learning_rate)

        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=1,
                restore_best_weights=True,
            )
        ]

        train_seq = TemporalSequence(
            np, X_train, y_train, BATCH_SIZE, training=True
        )

        history = model.fit(
            train_seq,
            validation_data=(X_val, y_val),
            epochs=TUNING_EPOCHS,
            callbacks=callbacks,
            verbose=0,
        )

        best_accuracy = max(
            history.history.get("val_accuracy", [0.0])
        )

        tf.keras.backend.clear_session()
        return float(best_accuracy)

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=42),
        pruner=optuna.pruners.MedianPruner(),
    )

    study.optimize(
        objective,
        n_trials=trials,
        catch=(Exception,),
        show_progress_bar=False,
    )

    if not study.trials:
        return {
            "learning_rate": 3e-4,
            "dropout_rate": 0.15,
        }

    best = study.best_trial

    log(f"[OPTUNA] Best validation accuracy: {best.value:.4f}")
    log(f"[OPTUNA] Best parameters: {best.params}")

    return dict(best.params)


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------

def attempt_pruning(tf, tfmot, model, X_train, y_train, X_val, y_val):
    if tfmot is None:
        log("[PRUNE] TensorFlow Model Optimization unavailable; skipped.")
        return model, False

    section("MODEL PRUNING")

    try:
        prune_schedule = tfmot.sparsity.keras.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.30,
            begin_step=0,
            end_step=max(1, (len(X_train) // BATCH_SIZE) * 3),
        )

        pruned_model = tfmot.sparsity.keras.prune_low_magnitude(
            model,
            pruning_schedule=prune_schedule,
        )

        # Recompile with a fresh optimizer.
        compile_model(tf, pruned_model, 1e-4)

        callbacks = [
            tfmot.sparsity.keras.UpdatePruningStep(),
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=2,
                restore_best_weights=True,
            ),
        ]

        train_seq = TemporalSequence(
            np, X_train, y_train, BATCH_SIZE, training=True
        )

        pruned_model.fit(
            train_seq,
            validation_data=(X_val, y_val),
            epochs=5,
            callbacks=callbacks,
            verbose=1,
        )

        stripped = tfmot.sparsity.keras.strip_pruning(pruned_model)
        log("[PRUNE] Pruning completed successfully.")
        return stripped, True

    except Exception as exc:
        log(f"[PRUNE] Skipped safely: {exc}")
        return model, False


# ---------------------------------------------------------------------------
# Quantization
# ---------------------------------------------------------------------------

def attempt_quantization(tf, tfmot, model):
    if tfmot is None:
        log("[QUANT] TensorFlow Model Optimization unavailable; skipped.")
        return model, False

    section("MODEL QUANTIZATION")

    try:
        quantized = tfmot.quantization.keras.quantize_model(model)
        log("[QUANT] Full-model quantization succeeded.")
        return quantized, True
    except Exception as exc:
        log(
            "[QUANT] Full-model quantization is not compatible with this "
            f"architecture/version: {exc}"
        )
        log("[QUANT] Keeping the validated floating-point model.")
        return model, False


# ---------------------------------------------------------------------------
# System information
# ---------------------------------------------------------------------------

def collect_system_metrics(psutil) -> dict[str, Any]:
    data = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
    }

    if psutil is not None:
        try:
            data["cpu_percent"] = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            data["memory_percent"] = memory.percent
            data["memory_total_gb"] = memory.total / (1024 ** 3)
            data["memory_available_gb"] = memory.available / (1024 ** 3)
        except Exception as exc:
            data["psutil_error"] = str(exc)

    return data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    section(f"{APP_NAME} v{APP_VERSION}")
    log("[START] Initializing.")

    try:
        library_status = ensure_libraries()
        np, tf, optuna, tfmot, psutil = load_runtime()

        hardware = detect_hardware(tf)
        configure_precision(tf, hardware)

        system_metrics = collect_system_metrics(psutil)

        section("DATA PREPARATION")
        X, y = load_temporal_data(
            np,
            seq_length=SEQ_LENGTH,
            num_samples=SYNTHETIC_SAMPLES,
            height=IMAGE_HEIGHT,
            width=IMAGE_WIDTH,
            channels=CHANNELS,
            num_classes=NUM_CLASSES,
        )

        log(f"[DATA] X shape: {X.shape}")
        log(f"[DATA] y shape: {y.shape}")

        X_train, X_val, y_train, y_val = split_data(np, X, y)

        log(f"[DATA] Training samples: {len(X_train)}")
        log(f"[DATA] Validation samples: {len(X_val)}")

        input_shape = (
            SEQ_LENGTH,
            IMAGE_HEIGHT,
            IMAGE_WIDTH,
            CHANNELS,
        )

        params = tune_hyperparameters(
            tf,
            np,
            optuna,
            X_train,
            y_train,
            X_val,
            y_val,
            input_shape,
            NUM_CLASSES,
            trials=TUNING_TRIALS,
        )

        learning_rate = float(params["learning_rate"])
        dropout_rate = float(params["dropout_rate"])

        section("FINAL MODEL")

        model = build_temporal_resnet(
            tf,
            input_shape,
            num_classes=NUM_CLASSES,
            dropout_rate=dropout_rate,
        )
        compile_model(tf, model, learning_rate)

        model.summary(print_fn=log)

        train_seq = TemporalSequence(
            np,
            X_train,
            y_train,
            BATCH_SIZE,
            training=True,
        )

        callbacks = [
            tf.keras.callbacks.ModelCheckpoint(
                str(MODEL_FILE),
                monitor="val_accuracy",
                mode="max",
                save_best_only=True,
            ),
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=4,
                restore_best_weights=True,
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor="val_loss",
                factor=0.5,
                patience=2,
                min_lr=1e-6,
            ),
        ]

        history = model.fit(
            train_seq,
            validation_data=(X_val, y_val),
            epochs=FINAL_EPOCHS,
            callbacks=callbacks,
            verbose=1,
        )

        baseline_benchmark = benchmark_model(
            model,
            X_val,
            y_val,
            BATCH_SIZE,
        )

        optimized_model, pruned = attempt_pruning(
            tf,
            tfmot,
            model,
            X_train,
            y_train,
            X_val,
            y_val,
        )

        optimized_model, quantized = attempt_quantization(
            tf,
            tfmot,
            optimized_model,
        )

        # Saving can fail for unsupported quantized layers; fall back safely.
        try:
            optimized_model.save(OPTIMIZED_MODEL_FILE)
            saved_path = str(OPTIMIZED_MODEL_FILE)
        except Exception as exc:
            log(f"[SAVE] Optimized save failed: {exc}")
            model.save(MODEL_FILE)
            saved_path = str(MODEL_FILE)

        optimized_benchmark = benchmark_model(
            optimized_model,
            X_val,
            y_val,
            BATCH_SIZE,
        )

        report = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hardware": asdict(hardware),
            "system": system_metrics,
            "libraries": library_status,
            "configuration": {
                "sequence_length": SEQ_LENGTH,
                "image_height": IMAGE_HEIGHT,
                "image_width": IMAGE_WIDTH,
                "channels": CHANNELS,
                "classes": NUM_CLASSES,
                "batch_size": BATCH_SIZE,
                "learning_rate": learning_rate,
                "dropout_rate": dropout_rate,
            },
            "training": {
                "epochs_requested": FINAL_EPOCHS,
                "epochs_completed": len(
                    history.history.get("loss", [])
                ),
                "best_validation_accuracy": float(
                    max(history.history.get("val_accuracy", [0.0]))
                ),
                "best_validation_loss": float(
                    min(history.history.get("val_loss", [0.0]))
                ),
            },
            "optimization": {
                "pruning_applied": pruned,
                "quantization_applied": quantized,
            },
            "benchmark_before_optimization": baseline_benchmark,
            "benchmark_after_optimization": optimized_benchmark,
            "saved_model": saved_path,
        }

        with REPORT_FILE.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        section("COMPLETE")
        log(f"[SAVE] Model: {saved_path}")
        log(f"[SAVE] Report: {REPORT_FILE}")
        log(f"[SAVE] Log: {LOG_FILE}")
        log("[DONE] Training and optimization completed.")

        return 0

    except KeyboardInterrupt:
        log("[STOP] User interrupted the program.")
        return 130

    except Exception as exc:
        log(f"[FATAL] {type(exc).__name__}: {exc}")
        log(traceback.format_exc())
        log(f"[FATAL] Full log saved to: {LOG_FILE}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
