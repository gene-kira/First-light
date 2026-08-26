#!/usr/bin/env python3
# tensorflow_temporal_cnn_gui.py

# ============================================================
# AUTOLOADER FOR ALL NECESSARY LIBRARIES
# ============================================================

import importlib
import subprocess
import sys
import logging

logging.basicConfig(
    filename='autoloader.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

REQUIRED_LIBS = [
    "numpy",
    "matplotlib",
    "sklearn",
    "tensorflow",
    "optuna",
    "tensorflow_model_optimization",
    "PyQt5",
]

def install_package(pkg):
    logging.warning(f"Attempting to install missing package: {pkg}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        logging.info(f"Successfully installed {pkg}")
    except Exception as e:
        logging.error(f"Failed to install {pkg}: {e}")

def autoload_libraries():
    for pkg in REQUIRED_LIBS:
        try:
            importlib.import_module(pkg)
            logging.info(f"Loaded library: {pkg}")
        except ImportError:
            logging.error(f"Library missing: {pkg}")
            install_package(pkg)
            try:
                importlib.import_module(pkg)
                logging.info(f"Loaded after install: {pkg}")
            except Exception as e:
                logging.critical(f"Failed to load {pkg} even after install: {e}")

autoload_libraries()

# ============================================================
# IMPORTS (AFTER AUTOLOADER)
# ============================================================

import numpy as np
import matplotlib
matplotlib.use("Agg")  # headless-safe
import matplotlib.pyplot as plt

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
    log_loss,
    roc_auc_score
)

import tensorflow as tf
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping
from tensorflow_model_optimization.sparsity import keras as sparsity
import optuna

from PyQt5 import QtWidgets, QtCore, QtGui
import threading
import time
import os

# ============================================================
# GLOBAL LOGGING FOR TRAINING
# ============================================================

logging.basicConfig(
    filename='model_training.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================================
# SAFE TENSORFLOW INITIALIZATION (GPU/CPU AUTO-FALLBACK)
# ============================================================

def safe_tf_init():
    logging.info("Initializing TensorFlow environment...")
    try:
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                tf.config.experimental.set_memory_growth(gpus[0], True)
                logging.info("GPU detected and initialized.")
                return "GPU"
            except Exception as e:
                logging.error(f"GPU initialization failed: {e}")
                logging.warning("Falling back to CPU.")
                tf.config.set_visible_devices([], 'GPU')
                return "CPU"
        else:
            logging.warning("No GPU detected. Using CPU.")
            return "CPU"
    except Exception as e:
        logging.error(f"TensorFlow failed to initialize: {e}")
        logging.warning("Forcing CPU mode.")
        tf.config.set_visible_devices([], 'GPU')
        return "CPU"

DEVICE_MODE = safe_tf_init()
logging.info(f"TensorFlow running in {DEVICE_MODE} mode.")

# ============================================================
# GLOBAL DATA HOLDERS
# ============================================================

X_train = None
X_val = None
y_train = None
y_val = None

# ============================================================
# DATA LOADING
# ============================================================

def load_and_preprocess_data(seq_length=3, num_samples=1000, height=64, width=64, channels=3):
    X_seq = np.random.rand(num_samples, seq_length, height, width, channels).astype(np.float32)
    y_seq = np.random.randint(0, 2, num_samples).astype(np.float32)
    return X_seq, y_seq

# ============================================================
# PLOTTING
# ============================================================

def plot_roc_curve(y_true, y_scores):
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc_val = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc_val)
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.savefig("roc_curve.png")
    plt.close()
    logging.info("ROC curve saved as roc_curve.png")

def plot_precision_recall_curve(y_true, y_scores):
    precision, recall, _ = precision_recall_curve(y_true, y_scores)
    average_precision = average_precision_score(y_true, y_scores)

    plt.figure()
    plt.plot(recall, precision, color='b', label='AP={0:0.2f}'.format(average_precision))
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower left")
    plt.savefig("precision_recall_curve.png")
    plt.close()
    logging.info("Precision-Recall curve saved as precision_recall_curve.png")

# ============================================================
# MODEL BUILDING
# ============================================================

def build_temporal_cnn(input_shape, num_classes):
    model = tf.keras.Sequential([
        tf.keras.layers.Conv3D(32, (3, 3, 3), activation='relu', input_shape=input_shape),
        tf.keras.layers.MaxPooling3D((2, 2, 2)),
        tf.keras.layers.Conv3D(64, (3, 3, 3), activation='relu'),
        tf.keras.layers.MaxPooling3D((2, 2, 2)),
        tf.keras.layers.Flatten(),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.Dropout(0.5),
        tf.keras.layers.Dense(num_classes, activation='sigmoid')
    ])
    return model

# ============================================================
# PRUNING (SAFE)
# ============================================================

def apply_pruning(model):
    pruning_params = {
        "pruning_schedule": sparsity.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.5,
            begin_step=0,
            end_step=2000
        )
    }

    def prune_layer(layer):
        if isinstance(layer, (tf.keras.layers.Conv3D, tf.keras.layers.Dense)):
            return sparsity.prune_low_magnitude(layer, **pruning_params)
        return layer

    pruned = tf.keras.models.clone_model(model, clone_function=prune_layer)
    pruned.build(model.input_shape)
    return pruned

# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(model, X_val, y_val):
    y_scores = model.predict(X_val).ravel()
    y_pred = (y_scores > 0.5).astype(int)

    class_report = classification_report(y_val, y_pred, target_names=['Class 0', 'Class 1'])
    logging.info("\nClassification Report:\n" + class_report)

    conf_matrix = confusion_matrix(y_val, y_pred)
    logging.info("Confusion Matrix:\n" + str(conf_matrix))

    roc_auc_val = roc_auc_score(y_val, y_scores)
    logging.info(f"ROC-AUC Score: {roc_auc_val}")

    plot_roc_curve(y_val, y_scores)

    pr_auc = average_precision_score(y_val, y_scores)
    logging.info(f"PR-AUC Score: {pr_auc}")

    plot_precision_recall_curve(y_val, y_scores)

    logloss = log_loss(y_val, y_scores)
    logging.info(f"Log-Loss: {logloss}")

# ============================================================
# OPTUNA OBJECTIVE
# ============================================================

def objective(trial):
    global X_train, X_val, y_train, y_val

    learning_rate = trial.suggest_loguniform('learning_rate', 1e-5, 1e-2)

    input_shape = (X_train.shape[1], X_train.shape[2], X_train.shape[3], X_train.shape[4])
    num_classes = 1
    model = build_temporal_cnn(input_shape, num_classes)

    optimizer = tf.keras.optimizers.Adam(learning_rate=learning_rate)
    loss_fn = tf.keras.losses.BinaryCrossentropy()
    model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])

    history = model.fit(
        X_train, y_train,
        batch_size=32,
        epochs=10,
        validation_data=(X_val, y_val),
        verbose=0
    )

    val_loss, val_accuracy = model.evaluate(X_val, y_val, verbose=0)
    logging.info(f"Trial {trial.number} - LR: {learning_rate}, Val Acc: {val_accuracy}")
    return val_accuracy

# ============================================================
# TRAINING PIPELINE (RUNS IN BACKGROUND THREAD)
# ============================================================

class TrainingRunner(QtCore.QObject):
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()

    def run(self):
        try:
            self.progress.emit("Loading and preprocessing data...")
            X_seq, y_seq = load_and_preprocess_data()
            split_idx = int(0.8 * len(X_seq))

            global X_train, X_val, y_train, y_val
            X_train, X_val = X_seq[:split_idx], X_seq[split_idx:]
            y_train, y_val = y_seq[:split_idx], y_seq[split_idx:]

            self.progress.emit("Starting Optuna study...")
            study = optuna.create_study(direction='maximize')
            study.optimize(objective, n_trials=10)

            best_trial = study.best_trial
            logging.info(f"Best trial: {best_trial.number} with accuracy: {best_trial.value}")
            for key, value in best_trial.params.items():
                logging.info(f"{key}: {value}")

            self.progress.emit("Building best model...")
            input_shape = (X_train.shape[1], X_train.shape[2], X_train.shape[3], X_train.shape[4])
            num_classes = 1
            best_model = build_temporal_cnn(input_shape, num_classes)
            best_params = best_trial.params
            optimizer = tf.keras.optimizers.Adam(learning_rate=best_params['learning_rate'])
            loss_fn = tf.keras.losses.BinaryCrossentropy()
            best_model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])

            checkpoint_path = "checkpoints"
            os.makedirs(checkpoint_path, exist_ok=True)
            checkpoint_file = os.path.join(checkpoint_path, "best_cp-{epoch:04d}.ckpt")
            cp_callback = ModelCheckpoint(filepath=checkpoint_file, save_weights_only=True, verbose=1)
            early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

            self.progress.emit("Training best model...")
            best_model.fit(
                X_train, y_train,
                batch_size=32,
                epochs=50,
                validation_data=(X_val, y_val),
                callbacks=[cp_callback, early_stopping],
                verbose=1
            )

            self.progress.emit("Evaluating best model...")
            evaluate_model(best_model, X_val, y_val)

            self.progress.emit("Applying pruning...")
            pruned_model = apply_pruning(best_model)
            pruned_model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])

            pruned_model.fit(
                X_train, y_train,
                batch_size=32,
                epochs=10,
                validation_data=(X_val, y_val),
                callbacks=[cp_callback, early_stopping],
                verbose=1
            )

            sparsity.strip_pruning(pruned_model)

            self.progress.emit("Evaluating pruned model...")
            evaluate_model(pruned_model, X_val, y_val)

            self.progress.emit("Converting to TFLite...")
            converter = tf.lite.TFLiteConverter.from_keras_model(pruned_model)
            tflite_model = converter.convert()

            with open('pruned_quantized_model.tflite', 'wb') as f:
                f.write(tflite_model)

            logging.info("Quantized and pruned model saved as pruned_quantized_model.tflite")
            self.progress.emit("Training pipeline completed successfully.")
        except Exception as e:
            logging.error(f"Training pipeline failed: {e}")
            self.progress.emit(f"ERROR: {e}")
        finally:
            self.finished.emit()

# ============================================================
# GUI TO MONITOR TRAINING
# ============================================================

class TrainingMonitor(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TensorFlow Temporal CNN Training Monitor")
        self.resize(900, 600)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        self.status_label = QtWidgets.QLabel("Status: Idle")
        self.status_label.setFont(QtGui.QFont("Segoe UI", 10))
        layout.addWidget(self.status_label)

        self.device_label = QtWidgets.QLabel(f"Device Mode: {DEVICE_MODE}")
        layout.addWidget(self.device_label)

        self.start_button = QtWidgets.QPushButton("Start Training")
        self.start_button.clicked.connect(self.start_training)
        layout.addWidget(self.start_button)

        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QtGui.QFont("Consolas", 9))
        layout.addWidget(self.log_view)

        self.setCentralWidget(central)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh_logs)
        self.timer.start()

        self.training_thread = None
        self.runner = None

    def start_training(self):
        if self.training_thread is not None:
            self.status_label.setText("Status: Training already running")
            return

        self.status_label.setText("Status: Starting training...")
        self.runner = TrainingRunner()
        self.runner.progress.connect(self.on_progress)
        self.runner.finished.connect(self.on_finished)

        self.training_thread = threading.Thread(target=self.runner.run, daemon=True)
        self.training_thread.start()

    def on_progress(self, msg):
        self.status_label.setText(f"Status: {msg}")
        self.log_view.appendPlainText(msg)

    def on_finished(self):
        self.status_label.setText("Status: Idle (Finished)")
        self.training_thread = None

    def refresh_logs(self):
        try:
            if os.path.exists("model_training.log"):
                with open("model_training.log", "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                # show last ~100 lines
                tail = "".join(lines[-100:])
                self.log_view.setPlainText(tail)
        except Exception:
            pass

# ============================================================
# MAIN ENTRY
# ============================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    app.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)

    win = TrainingMonitor()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
