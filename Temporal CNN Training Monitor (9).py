#!/usr/bin/env python3
"""
TensorFlow Temporal CNN Training Monitor - upgraded, crash-resistant version.

Changes:
- No runtime pip installs: startup remains responsive and failures are reported clearly.
- Correct dependency/import checks.
- Training starts automatically when the window opens.
- Uses QThread instead of a raw threading.Thread for Qt-safe background execution.
- Smaller safe default dataset and valid Conv3D architecture.
- Optuna API updated for current releases.
- Pruning callbacks and model checkpointing corrected.
- Atomic log/status reporting and better exception tracebacks.
- TFLite dynamic-range quantization enabled.
- GUI remains responsive and can stop training between major stages.
"""

import os
import sys
import time
import logging
import traceback
import importlib
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
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping, Callback
from tensorflow_model_optimization.sparsity import keras as sparsity
import optuna

from PyQt5 import QtWidgets, QtCore, QtGui


# --------------------------- configuration ---------------------------

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "training_output"
CHECKPOINT_DIR = OUTPUT_DIR / "checkpoints"
LOG_FILE = OUTPUT_DIR / "model_training.log"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s",
)

# Reduce TensorFlow console noise without hiding real Python exceptions.
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
optuna.logging.set_verbosity(optuna.logging.WARNING)

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


# ------------------------------ data ---------------------------------

def load_and_preprocess_data(
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


# ------------------------------- model -------------------------------

def build_temporal_cnn(input_shape):
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
    return tf.keras.Model(inputs, outputs, name="temporal_cnn")


def compile_model(model, learning_rate):
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss=tf.keras.losses.BinaryCrossentropy(),
        metrics=["accuracy"],
    )


# ------------------------------ pruning ------------------------------

def apply_pruning(model, end_step):
    end_step = max(1, int(end_step))
    pruning_params = {
        "pruning_schedule": sparsity.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.50,
            begin_step=0,
            end_step=end_step,
        )
    }

    def clone_layer(layer):
        if isinstance(layer, (tf.keras.layers.Conv3D, tf.keras.layers.Dense)):
            return sparsity.prune_low_magnitude(layer, **pruning_params)
        return layer

    pruned = tf.keras.models.clone_model(model, clone_function=clone_layer)
    pruned.set_weights(model.get_weights())
    return pruned


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


# --------------------------- training worker -------------------------

class StopRequested(Exception):
    pass


class TrainingWorker(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    error = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()
    completed = QtCore.pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._stop_requested = False

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
            self._emit("Initializing TensorFlow training pipeline...")
            self._check_stop()

            self._emit("Loading and preprocessing demo data...")
            X_seq, y_seq = load_and_preprocess_data()
            split_idx = int(0.8 * len(X_seq))
            X_train, X_val = X_seq[:split_idx], X_seq[split_idx:]
            y_train, y_val = y_seq[:split_idx], y_seq[split_idx:]

            if len(X_train) == 0 or len(X_val) == 0:
                raise ValueError("Dataset split produced an empty training or validation set.")

            input_shape = tuple(X_train.shape[1:])
            self._emit(
                f"Data ready: train={len(X_train)}, validation={len(X_val)}, "
                f"input={input_shape}"
            )

            self._check_stop()
            self._emit(f"Running {OPTUNA_TRIALS} Optuna optimization trials...")

            def objective(trial):
                self._check_stop()
                tf.keras.backend.clear_session()
                learning_rate = trial.suggest_float(
                    "learning_rate", 1e-4, 3e-3, log=True
                )
                model = build_temporal_cnn(input_shape)
                compile_model(model, learning_rate)
                callbacks = [
                    EarlyStopping(
                        monitor="val_loss",
                        patience=1,
                        restore_best_weights=True,
                    )
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
            self._check_stop()

            completed_trials = [
                t for t in study.trials
                if t.state == optuna.trial.TrialState.COMPLETE and t.value is not None
            ]
            if not completed_trials:
                raise RuntimeError("No Optuna trial completed successfully.")

            best_trial = study.best_trial
            best_lr = float(best_trial.params["learning_rate"])
            self._emit(
                f"Best learning rate: {best_lr:.6g}; "
                f"validation accuracy: {best_trial.value:.4f}"
            )

            tf.keras.backend.clear_session()
            self._emit("Building and training the best model...")
            best_model = build_temporal_cnn(input_shape)
            compile_model(best_model, best_lr)

            checkpoint_file = CHECKPOINT_DIR / "best_model.weights.h5"
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
            ]

            best_model.fit(
                X_train, y_train,
                batch_size=BATCH_SIZE,
                epochs=FINAL_EPOCHS,
                validation_data=(X_val, y_val),
                callbacks=callbacks,
                verbose=0,
            )
            self._check_stop()

            self._emit("Evaluating best model...")
            metrics = evaluate_model(best_model, X_val, y_val, prefix="best_model")

            self._check_stop()
            self._emit("Applying magnitude pruning...")
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
            ]

            pruned_model.fit(
                X_train, y_train,
                batch_size=BATCH_SIZE,
                epochs=PRUNE_EPOCHS,
                validation_data=(X_val, y_val),
                callbacks=prune_callbacks,
                verbose=0,
            )
            self._check_stop()

            self._emit("Stripping pruning wrappers and saving models...")
            stripped_model = sparsity.strip_pruning(pruned_model)
            compile_model(stripped_model, best_lr)

            keras_path = OUTPUT_DIR / "pruned_model.keras"
            stripped_model.save(str(keras_path))

            self._emit("Evaluating pruned model...")
            pruned_metrics = evaluate_model(
                stripped_model, X_val, y_val, prefix="pruned_model"
            )

            self._check_stop()
            self._emit("Converting model to quantized TFLite...")
            converter = tf.lite.TFLiteConverter.from_keras_model(stripped_model)
            converter.optimizations = [tf.lite.Optimize.DEFAULT]
            tflite_model = converter.convert()

            tflite_path = OUTPUT_DIR / "pruned_quantized_model.tflite"
            tflite_path.write_bytes(tflite_model)

            result = {
                "device": DEVICE_MODE,
                "best_learning_rate": best_lr,
                "best_trial_accuracy": float(best_trial.value),
                "best_model_metrics": metrics,
                "pruned_model_metrics": pruned_metrics,
                "keras_model": str(keras_path),
                "tflite_model": str(tflite_path),
            }
            self._emit("Training pipeline completed successfully.")
            self.completed.emit(result)

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
        self.restart_button.clicked.connect(self.start_training)
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

        # Automatic startup after the Qt event loop is active.
        QtCore.QTimer.singleShot(250, self.start_training)

    def start_training(self):
        if self.running:
            self.append_log("Training is already running.")
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
        if self.worker is not None and self.running:
            self.worker.request_stop()
            self.stop_button.setEnabled(False)

    def on_progress(self, message):
        self.status_label.setText(f"Status: {message}")
        self.append_log(message)

    def on_error(self, details):
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
        self.append_log(
            "OUTPUTS:\n"
            f"  Keras model: {result['keras_model']}\n"
            f"  TFLite model: {result['tflite_model']}\n"
        )

    def on_finished(self):
        self.running = False
        self.worker = None
        self.thread = None
        self.restart_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if not self.status_label.text().startswith("Status: ERROR"):
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
                "Training is still running. Request a safe stop and close when it finishes?",
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


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Temporal CNN Training Monitor")
    window = TrainingMonitor()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
