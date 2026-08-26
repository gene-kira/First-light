import logging
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc, precision_recall_curve, average_precision_score, log_loss
import tensorflow as tf
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping
import optuna
from tensorflow_model_optimization.sparsity import keras as sparsity
from tensorflow.keras.preprocessing.image import ImageDataGenerator

# Set up logging
logging.basicConfig(filename='model_training.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Global variables to store training and validation data
X_train = None
X_val = None
y_train = None
y_val = None

# Function to load and preprocess data
def load_and_preprocess_data(seq_length=3, num_samples=1000, height=64, width=64, channels=3):
    X_seq = np.random.rand(num_samples, seq_length, height, width, channels)  # Random sequence of images
    y_seq = np.random.randint(0, 2, num_samples)  # Binary labels for demonstration

    return X_seq, y_seq

# Function to plot ROC curve
def plot_roc_curve(y_true, y_scores):
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.savefig("roc_curve.png")
    logging.info("ROC curve saved as roc_curve.png")

# Function to plot Precision-Recall curve
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
    logging.info("Precision-Recall curve saved as precision_recall_curve.png")

# Function to evaluate the model with more sophisticated metrics
def evaluate_model(model, X_val, y_val):
    # Predict probabilities
    y_scores = model.predict(X_val).ravel()
    
    # Predict classes
    y_pred = (y_scores > 0.5).astype(int)
    
    # Generate classification report
    class_report = classification_report(y_val, y_pred, target_names=['Class 0', 'Class 1'])
    logging.info("\nClassification Report:\n" + class_report)
    
    # Generate confusion matrix
    conf_matrix = confusion_matrix(y_val, y_pred)
    logging.info("Confusion Matrix:\n" + str(conf_matrix))
    
    # Calculate ROC-AUC score
    roc_auc = roc_auc_score(y_val, y_scores)
    logging.info(f"ROC-AUC Score: {roc_auc}")
    
    # Plot ROC curve
    plot_roc_curve(y_val, y_scores)
    
    # Calculate PR-AUC score
    pr_auc = average_precision_score(y_val, y_scores)
    logging.info(f"PR-AUC Score: {pr_auc}")
    
    # Plot Precision-Recall curve
    plot_precision_recall_curve(y_val, y_scores)
    
    # Calculate Log-Loss (Cross-Entropy Loss)
    logloss = log_loss(y_val, y_scores)
    logging.info(f"Log-Loss: {logloss}")

# Main function
def main():
    global X_train, X_val, y_train, y_val
    
    # Load and preprocess data
    seq_length = 3
    X_seq, y_seq = load_and_preprocess_data(seq_length=seq_length)
    
    # Split data into training and validation sets
    split_idx = int(0.8 * len(X_seq))
    X_train, X_val = X_seq[:split_idx], X_seq[split_idx:]
    y_train, y_val = y_seq[:split_idx], y_seq[split_idx:]
    
    # Hyperparameter tuning with Optuna
    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=10)
    
    # Best trial information
    best_trial = study.best_trial
    logging.info(f"Best trial: {best_trial.number} with accuracy: {best_trial.value}")
    for key, value in best_trial.params.items():
        logging.info(f"{key}: {value}")
    
    # Build and compile the best model
    input_shape = (X_train.shape[1], X_train.shape[2], X_train.shape[3], X_train.shape[4])
    num_classes = 1  # Binary classification for demonstration
    best_model = build_temporal_cnn(input_shape, num_classes)
    best_params = best_trial.params
    optimizer = tf.keras.optimizers.Adam(learning_rate=best_params['learning_rate'])
    loss_fn = tf.keras.losses.BinaryCrossentropy()
    best_model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])
    
    # Create data augmentor
    datagen = ImageDataGenerator(rescale=1./255)
    
    # Train the best model with callbacks
    checkpoint_path = "checkpoints/best_cp-{epoch:04d}.ckpt"
    cp_callback = ModelCheckpoint(filepath=checkpoint_path, save_weights_only=True, verbose=1)
    early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    
    best_model.fit(
        datagen.flow(X_train, y_train, batch_size=32),
        epochs=50,
        validation_data=(X_val, y_val),
        callbacks=[cp_callback, early_stopping],
        verbose=1
    )
    
    # Evaluate the best model with sophisticated metrics
    evaluate_model(best_model, X_val, y_val)
    
    # Prune and quantize the best model
    pruned_model = sparsity.prune_low_magnitude(best_model)
    pruned_model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])
    
    pruned_model.fit(
        datagen.flow(X_train, y_train, batch_size=32),
        epochs=10,
        validation_data=(X_val, y_val),
        callbacks=[cp_callback, early_stopping],
        verbose=1
    )
    
    sparsity.strip_pruning(pruned_model)
    
    # Evaluate pruned model with sophisticated metrics
    evaluate_model(pruned_model, X_val, y_val)
    
    # Quantize the pruned model
    converter = tf.lite.TFLiteConverter.from_keras_model(pruned_model)
    tflite_model = converter.convert()
    
    # Save the quantized model to a file
    with open('pruned_quantized_model.tflite', 'wb') as f:
        f.write(tflite_model)
    
    logging.info("Quantized and pruned model saved as pruned_quantized_model.tflite")

# Objective function for Optuna
def objective(trial):
    # Suggest hyperparameters
    learning_rate = trial.suggest_loguniform('learning_rate', 1e-5, 1e-2)
    
    # Build and compile the model
    input_shape = (X_train.shape[1], X_train.shape[2], X_train.shape[3], X_train.shape[4])
    num_classes = 1  # Binary classification for demonstration
    model = build_temporal_cnn(input_shape, num_classes)
    
    optimizer = tf.keras.optimizers.Adam(learning_rate=learning_rate)
    loss_fn = tf.keras.losses.BinaryCrossentropy()
    model.compile(optimizer=optimizer, loss=loss_fn, metrics=['accuracy'])
    
    # Create data augmentor
    datagen = ImageDataGenerator(rescale=1./255)
    
    # Train the model
    history = model.fit(
        datagen.flow(X_train, y_train, batch_size=32),
        epochs=10,
        validation_data=(X_val, y_val),
        verbose=1
    )
    
    # Evaluate the model
    val_loss, val_accuracy = model.evaluate(X_val, y_val, verbose=1)
    return val_accuracy

# Function to build a temporal CNN model
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

if __name__ == "__main__":
    main()
