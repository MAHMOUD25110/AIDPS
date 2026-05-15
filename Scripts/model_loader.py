"""Handles loading of the trained machine learning model and scalers."""

import os
import joblib
from config import MODEL_PATH, SCALER_PATH, COLUMNS_PATH

def load_models():
    """Loads the trained model, scaler, and one-hot encoded columns structure."""
    try:
        model = joblib.load(MODEL_PATH)
        
        # Load scaler if it exists, otherwise return None for it
        scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
        
        # Load expected columns (to handle missing one-hot encoded columns)
        model_columns = joblib.load(COLUMNS_PATH) if os.path.exists(COLUMNS_PATH) else None
        
        print("[+] Models and preprocessing objects loaded successfully.")
        return model, scaler, model_columns
    except Exception as e:
        print(f"[-] Error loading models: {e}")
        return None, None, None
