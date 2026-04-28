#!/usr/bin/env python3
"""
ml/models.py
AI/ML Models for Cloud Security Threat Detection
────────────────────────────────────────────────
Models:
  1. Isolation Forest  – Anomaly detection
  2. LSTM Network      – Temporal threat prediction
  3. Random Forest     – Attack classification
  4. Risk Scoring NN   – Composite risk score (0-100)
"""

import os, json, logging, time
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, confusion_matrix

# TensorFlow / Keras
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (
    LSTM, Dense, Dropout, BatchNormalization, Input
)
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.optimizers import Adam

# Persistence
import joblib

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

MODEL_DIR = os.environ.get("MODEL_DIR", "/models")
os.makedirs(MODEL_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  1. ISOLATION FOREST – Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Detects anomalous security events using Isolation Forest.
    Features: request_rate, failed_auths, data_volume_mb, distinct_ips,
              hour_of_day, day_of_week, geo_risk_score, api_error_rate
    """
    FEATURES = [
        "request_rate", "failed_auths", "data_volume_mb",
        "distinct_ips", "hour_of_day", "day_of_week",
        "geo_risk_score", "api_error_rate",
    ]

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def _validate(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in self.FEATURES:
            if col not in df.columns:
                df[col] = 0.0
        return df[self.FEATURES].fillna(0)

    def fit(self, df: pd.DataFrame):
        X = self._validate(df)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        log.info("AnomalyDetector fitted on %d samples", len(df))

    def predict(self, df: pd.DataFrame) -> dict:
        if not self.is_fitted:
            raise RuntimeError("Model not fitted yet")
        X = self._validate(df)
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)            # 1=normal, -1=anomaly
        scores = self.model.score_samples(X_scaled)     # lower = more anomalous
        anomaly_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
        results = []
        for i, (pred, score) in enumerate(zip(preds, anomaly_scores)):
            results.append({
                "is_anomaly": bool(pred == -1),
                "anomaly_score": float(round(score, 4)),
                "severity": _score_to_severity(score),
            })
        return results

    def save(self):
        joblib.dump(self.model,  f"{MODEL_DIR}/isolation_forest.pkl")
        joblib.dump(self.scaler, f"{MODEL_DIR}/if_scaler.pkl")
        log.info("AnomalyDetector saved")

    def load(self):
        self.model  = joblib.load(f"{MODEL_DIR}/isolation_forest.pkl")
        self.scaler = joblib.load(f"{MODEL_DIR}/if_scaler.pkl")
        self.is_fitted = True
        log.info("AnomalyDetector loaded")


# ═══════════════════════════════════════════════════════════════════════════════
#  2. LSTM – Temporal Threat Prediction
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatPredictor:
    """
    LSTM model to predict security incidents 15 minutes ahead.
    Input: sliding window of time-series security metrics.
    Output: probability of incident in next window.
    """
    SEQ_LEN   = 12      # 12 × 5-min samples = 1 hour lookback
    N_FEATURES = 8
    THRESHOLD  = 0.5

    def __init__(self):
        self.model  = None
        self.scaler = StandardScaler()

    def _build_model(self):
        m = Sequential([
            LSTM(128, return_sequences=True, input_shape=(self.SEQ_LEN, self.N_FEATURES)),
            Dropout(0.3),
            BatchNormalization(),
            LSTM(64, return_sequences=True),
            Dropout(0.2),
            LSTM(32),
            Dropout(0.2),
            Dense(16, activation="relu"),
            Dense(1,  activation="sigmoid"),
        ])
        m.compile(optimizer=Adam(1e-3), loss="binary_crossentropy",
                  metrics=["accuracy", tf.keras.metrics.AUC(name="auc")])
        return m

    def _make_sequences(self, X: np.ndarray, y: np.ndarray):
        Xs, ys = [], []
        for i in range(len(X) - self.SEQ_LEN):
            Xs.append(X[i : i + self.SEQ_LEN])
            ys.append(y[i + self.SEQ_LEN])
        return np.array(Xs), np.array(ys)

    def fit(self, df: pd.DataFrame, label_col: str = "incident"):
        feature_cols = [c for c in df.columns if c != label_col]
        X = self.scaler.fit_transform(df[feature_cols].fillna(0).values)
        y = df[label_col].values
        X_seq, y_seq = self._make_sequences(X, y)
        X_tr, X_val, y_tr, y_val = train_test_split(X_seq, y_seq, test_size=0.2, random_state=42)

        self.model = self._build_model()
        callbacks = [
            EarlyStopping(patience=5, restore_best_weights=True),
            ModelCheckpoint(f"{MODEL_DIR}/lstm_best.keras", save_best_only=True),
        ]
        history = self.model.fit(
            X_tr, y_tr,
            validation_data=(X_val, y_val),
            epochs=50, batch_size=32,
            callbacks=callbacks, verbose=1,
        )
        val_acc = max(history.history["val_accuracy"])
        log.info("LSTM trained – best val_accuracy: %.4f", val_acc)
        return history

    def predict(self, recent_df: pd.DataFrame) -> dict:
        feature_cols = [c for c in recent_df.columns]
        X = self.scaler.transform(recent_df[feature_cols].fillna(0).values)
        if len(X) < self.SEQ_LEN:
            return {"probability": 0.0, "prediction": "insufficient_data"}
        seq = X[-self.SEQ_LEN:].reshape(1, self.SEQ_LEN, self.N_FEATURES)
        prob = float(self.model.predict(seq, verbose=0)[0][0])
        return {
            "probability": round(prob, 4),
            "prediction": "incident_likely" if prob >= self.THRESHOLD else "normal",
            "confidence": round(abs(prob - 0.5) * 2, 4),
        }

    def save(self):
        self.model.save(f"{MODEL_DIR}/lstm_model.keras")
        joblib.dump(self.scaler, f"{MODEL_DIR}/lstm_scaler.pkl")

    def load(self):
        self.model  = tf.keras.models.load_model(f"{MODEL_DIR}/lstm_model.keras")
        self.scaler = joblib.load(f"{MODEL_DIR}/lstm_scaler.pkl")


# ═══════════════════════════════════════════════════════════════════════════════
#  3. RANDOM FOREST – Attack Classification
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_CLASSES = [
    "DDoS", "DataExfiltration", "PrivilegeEscalation",
    "BruteForce", "Cryptomining", "Misconfiguration",
    "RansomwareIndicator", "Normal",
]

class AttackClassifier:
    """
    Multi-class Random Forest classifier to categorize threat types.
    Trained on labeled attack data.
    """
    FEATURES = [
        "request_rate", "failed_auths", "data_volume_mb",
        "distinct_ips", "cpu_spike", "network_bytes_out",
        "privileged_ops", "new_process_count",
        "dns_query_count", "port_scan_count",
    ]

    def __init__(self):
        self.model   = RandomForestClassifier(
            n_estimators=300, max_depth=15, min_samples_split=5,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        self.scaler  = StandardScaler()
        self.encoder = LabelEncoder()
        self.is_fitted = False

    def _validate(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in self.FEATURES:
            if col not in df.columns:
                df[col] = 0.0
        return df[self.FEATURES].fillna(0)

    def fit(self, df: pd.DataFrame, label_col: str = "attack_type"):
        X = self._validate(df)
        y = self.encoder.fit_transform(df[label_col])
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        X_tr_s = self.scaler.fit_transform(X_tr)
        X_te_s = self.scaler.transform(X_te)
        self.model.fit(X_tr_s, y_tr)
        self.is_fitted = True
        y_pred = self.model.predict(X_te_s)
        f1 = f1_score(y_te, y_pred, average="weighted")
        log.info("AttackClassifier F1 (weighted): %.4f", f1)
        log.info("\n%s", classification_report(y_te, y_pred,
                                               target_names=self.encoder.classes_))
        return {"f1_weighted": f1}

    def predict(self, df: pd.DataFrame) -> list:
        if not self.is_fitted:
            raise RuntimeError("Model not fitted")
        X = self._validate(df)
        X_s = self.scaler.transform(X)
        preds  = self.model.predict(X_s)
        probas = self.model.predict_proba(X_s)
        results = []
        for pred, proba in zip(preds, probas):
            top_class = self.encoder.inverse_transform([pred])[0]
            results.append({
                "attack_type": top_class,
                "confidence": float(round(proba.max(), 4)),
                "class_probabilities": {
                    cls: float(round(p, 4))
                    for cls, p in zip(self.encoder.classes_, proba)
                },
            })
        return results

    def feature_importance(self) -> dict:
        return dict(zip(self.FEATURES, self.model.feature_importances_.round(4).tolist()))

    def save(self):
        joblib.dump(self.model,   f"{MODEL_DIR}/random_forest.pkl")
        joblib.dump(self.scaler,  f"{MODEL_DIR}/rf_scaler.pkl")
        joblib.dump(self.encoder, f"{MODEL_DIR}/rf_encoder.pkl")

    def load(self):
        self.model   = joblib.load(f"{MODEL_DIR}/random_forest.pkl")
        self.scaler  = joblib.load(f"{MODEL_DIR}/rf_scaler.pkl")
        self.encoder = joblib.load(f"{MODEL_DIR}/rf_encoder.pkl")
        self.is_fitted = True


# ═══════════════════════════════════════════════════════════════════════════════
#  4. RISK SCORING NEURAL NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

class RiskScorer:
    """
    Neural network producing a risk score (0-100) for each security event.
    Combines: severity, target criticality, exploit availability, and context.
    """
    INPUT_DIM = 12

    def __init__(self):
        self.model  = None
        self.scaler = StandardScaler()

    def _build_model(self):
        inp = Input(shape=(self.INPUT_DIM,))
        x = Dense(64, activation="relu")(inp)
        x = BatchNormalization()(x)
        x = Dropout(0.3)(x)
        x = Dense(32, activation="relu")(x)
        x = Dropout(0.2)(x)
        x = Dense(16, activation="relu")(x)
        out = Dense(1, activation="sigmoid")(x)   # 0-1, will scale to 0-100
        m = Model(inp, out)
        m.compile(optimizer=Adam(5e-4), loss="mse", metrics=["mae"])
        return m

    def fit(self, df: pd.DataFrame, label_col: str = "risk_score"):
        feature_cols = [c for c in df.columns if c != label_col]
        X = self.scaler.fit_transform(df[feature_cols].fillna(0))
        y = (df[label_col] / 100).values   # normalise labels to 0-1
        X_tr, X_val, y_tr, y_val = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model = self._build_model()
        self.model.fit(
            X_tr, y_tr, validation_data=(X_val, y_val),
            epochs=100, batch_size=64,
            callbacks=[EarlyStopping(patience=10, restore_best_weights=True)],
            verbose=0,
        )
        val_mae = min(self.model.history.history["val_mae"])
        log.info("RiskScorer val_MAE: %.4f (in 0-100 scale: %.1f)", val_mae, val_mae * 100)

    def score(self, features: dict) -> float:
        df = pd.DataFrame([features])
        X = self.scaler.transform(df.fillna(0))
        raw = float(self.model.predict(X, verbose=0)[0][0])
        return round(raw * 100, 1)

    def save(self):
        self.model.save(f"{MODEL_DIR}/risk_scorer.keras")
        joblib.dump(self.scaler, f"{MODEL_DIR}/rs_scaler.pkl")

    def load(self):
        self.model  = tf.keras.models.load_model(f"{MODEL_DIR}/risk_scorer.keras")
        self.scaler = joblib.load(f"{MODEL_DIR}/rs_scaler.pkl")


# ═══════════════════════════════════════════════════════════════════════════════
#  Dataset Generator (for testing without real data)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_sample_dataset(n_samples: int = 10_000, save_path: str = "./data") -> dict:
    """Generate synthetic security logs for model training and testing."""
    os.makedirs(save_path, exist_ok=True)
    np.random.seed(42)

    # Normal traffic baseline
    normal_n = int(n_samples * 0.85)
    attack_n = n_samples - normal_n

    # ── Normal events ──
    normal = pd.DataFrame({
        "request_rate":     np.random.normal(50,  15,  normal_n).clip(0),
        "failed_auths":     np.random.poisson(2,      normal_n),
        "data_volume_mb":   np.random.exponential(10, normal_n).clip(0, 100),
        "distinct_ips":     np.random.randint(1, 20,  normal_n),
        "hour_of_day":      np.random.randint(0, 24,  normal_n),
        "day_of_week":      np.random.randint(0, 7,   normal_n),
        "geo_risk_score":   np.random.beta(2, 5,      normal_n),
        "api_error_rate":   np.random.beta(1, 20,     normal_n),
        "cpu_spike":        np.random.normal(30, 10,  normal_n).clip(0, 100),
        "network_bytes_out":np.random.exponential(1e6,normal_n),
        "privileged_ops":   np.random.poisson(1,      normal_n),
        "new_process_count":np.random.poisson(3,      normal_n),
        "dns_query_count":  np.random.poisson(20,     normal_n),
        "port_scan_count":  np.zeros(normal_n),
        "attack_type":      ["Normal"] * normal_n,
        "incident":         [0] * normal_n,
        "risk_score":       np.random.normal(15, 8, normal_n).clip(0, 40),
    })

    # ── Attack events ──
    attack_types = ["DDoS","DataExfiltration","PrivilegeEscalation",
                    "BruteForce","Cryptomining","Misconfiguration"]
    attacks = []
    per_type = attack_n // len(attack_types)
    for atype in attack_types:
        if atype == "DDoS":
            df = pd.DataFrame({
                "request_rate":     np.random.normal(5000, 1000, per_type).clip(0),
                "failed_auths":     np.random.poisson(5,  per_type),
                "data_volume_mb":   np.random.normal(500, 100, per_type).clip(0),
                "distinct_ips":     np.random.randint(100, 10000, per_type),
                "hour_of_day":      np.random.randint(0, 24, per_type),
                "day_of_week":      np.random.randint(0, 7,  per_type),
                "geo_risk_score":   np.random.beta(5, 2, per_type),
                "api_error_rate":   np.random.beta(8, 2, per_type),
                "cpu_spike":        np.random.normal(95, 3, per_type).clip(0, 100),
                "network_bytes_out":np.random.exponential(1e9, per_type),
                "privileged_ops":   np.random.poisson(1, per_type),
                "new_process_count":np.random.poisson(3, per_type),
                "dns_query_count":  np.random.poisson(20, per_type),
                "port_scan_count":  np.zeros(per_type),
                "attack_type":      [atype] * per_type,
                "incident":         [1] * per_type,
                "risk_score":       np.random.normal(85, 8, per_type).clip(60, 100),
            })
        elif atype == "BruteForce":
            df = pd.DataFrame({
                "request_rate":     np.random.normal(200, 50, per_type).clip(0),
                "failed_auths":     np.random.normal(300, 50, per_type).clip(0),
                "data_volume_mb":   np.random.exponential(5, per_type),
                "distinct_ips":     np.random.randint(1, 5, per_type),
                "hour_of_day":      np.random.randint(0, 6, per_type),   # night
                "day_of_week":      np.random.randint(0, 7, per_type),
                "geo_risk_score":   np.random.beta(4, 2, per_type),
                "api_error_rate":   np.random.beta(6, 2, per_type),
                "cpu_spike":        np.random.normal(40, 15, per_type).clip(0, 100),
                "network_bytes_out":np.random.exponential(1e5, per_type),
                "privileged_ops":   np.random.poisson(2, per_type),
                "new_process_count":np.random.poisson(5, per_type),
                "dns_query_count":  np.random.poisson(10, per_type),
                "port_scan_count":  np.random.poisson(1, per_type),
                "attack_type":      [atype] * per_type,
                "incident":         [1] * per_type,
                "risk_score":       np.random.normal(70, 10, per_type).clip(50, 95),
            })
        else:
            # Generic attack pattern
            df = pd.DataFrame({
                "request_rate":     np.random.normal(150, 50, per_type).clip(0),
                "failed_auths":     np.random.poisson(20, per_type),
                "data_volume_mb":   np.random.normal(200, 80, per_type).clip(0),
                "distinct_ips":     np.random.randint(5, 50, per_type),
                "hour_of_day":      np.random.randint(0, 24, per_type),
                "day_of_week":      np.random.randint(0, 7, per_type),
                "geo_risk_score":   np.random.beta(3, 2, per_type),
                "api_error_rate":   np.random.beta(3, 2, per_type),
                "cpu_spike":        np.random.normal(70, 20, per_type).clip(0, 100),
                "network_bytes_out":np.random.exponential(5e7, per_type),
                "privileged_ops":   np.random.poisson(10, per_type),
                "new_process_count":np.random.poisson(15, per_type),
                "dns_query_count":  np.random.poisson(50, per_type),
                "port_scan_count":  np.random.poisson(5, per_type),
                "attack_type":      [atype] * per_type,
                "incident":         [1] * per_type,
                "risk_score":       np.random.normal(75, 12, per_type).clip(55, 100),
            })
        attacks.append(df)

    full = pd.concat([normal] + attacks, ignore_index=True).sample(frac=1, random_state=42)
    path = os.path.join(save_path, "security_dataset.csv")
    full.to_csv(path, index=False)
    log.info("Dataset saved → %s  (shape: %s)", path, full.shape)
    return {"path": path, "shape": full.shape, "class_dist": full["attack_type"].value_counts().to_dict()}


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _score_to_severity(score: float) -> str:
    if score >= 0.9:  return "critical"
    if score >= 0.7:  return "high"
    if score >= 0.5:  return "medium"
    if score >= 0.3:  return "low"
    return "info"


# ═══════════════════════════════════════════════════════════════════════════════
#  Training Pipeline (run once / via MLOps)
# ═══════════════════════════════════════════════════════════════════════════════

def train_all_models():
    log.info("═══ Generating dataset ═══")
    meta = generate_sample_dataset(n_samples=15_000, save_path="./data")
    df = pd.read_csv(meta["path"])

    log.info("═══ Training Isolation Forest ═══")
    normal_df = df[df["attack_type"] == "Normal"]
    anomaly_det = AnomalyDetector(contamination=0.05)
    anomaly_det.fit(normal_df)
    anomaly_det.save()

    log.info("═══ Training Attack Classifier ═══")
    classifier = AttackClassifier()
    metrics = classifier.fit(df)
    classifier.save()
    log.info("Classifier metrics: %s", metrics)

    log.info("═══ Training Risk Scorer ═══")
    risk_features = [c for c in df.columns if c not in ("attack_type","incident","risk_score")]
    risk_df = df[risk_features + ["risk_score"]]
    scorer = RiskScorer()
    scorer.fit(risk_df)
    scorer.save()

    log.info("═══ All models trained & saved to %s ═══", MODEL_DIR)
    return {"anomaly_detector": "ok", "classifier": metrics, "risk_scorer": "ok"}


if __name__ == "__main__":
    import sys
    if "--train" in sys.argv:
        results = train_all_models()
        print(json.dumps(results, indent=2))
    else:
        # Demo inference
        generate_sample_dataset(n_samples=1000, save_path="./data")
        print("Dataset generated. Run with --train to train models.")
