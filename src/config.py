"""Configuration settings for the IDPS pipeline."""
import os

# Base directory is the project root (parent of src/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

MODEL_PATH = os.path.join(BASE_DIR, "Models", "rf_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "Models", "scaler.pkl")
COLUMNS_PATH = os.path.join(BASE_DIR, "Models", "onehot_columns.pkl")
DB_PATH = os.path.join(BASE_DIR, "idps_logs.db")
BLOCK_DURATION_MINUTES = 60
