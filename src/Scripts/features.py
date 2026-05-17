"""Feature extraction and preprocessing logic for network packets."""

import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP

def extract_features(packet):
    """
    Extracts features from a Scapy packet to match the KDD dataset format.
    Note: Real KDD dataset features (like 'num_failed_logins', 'srv_count') require 
    full connection state tracking over time. This function approximates those 
    features for a single packet so the model can process it in real-time.
    """
    features = {
        'duration': 0,
        'protocol_type': 'unknown',
        'service': 'private', # Default service
        'flag': 'SF',         # Default flag
        'src_bytes': 0,
        'dst_bytes': 0,
        'land': 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': 1,
        'srv_count': 1,
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 1,
        'dst_host_srv_count': 1,
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 1.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }

    if IP in packet:
        features['src_bytes'] = len(packet)
        
        # Check if src and dst IP are the same (Land attack feature)
        if packet[IP].src == packet[IP].dst:
            features['land'] = 1
            
        if TCP in packet:
            features['protocol_type'] = 'tcp'
            
            # Simple service approximation based on common ports
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                features['service'] = 'http'
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                features['service'] = 'ftp'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                features['service'] = 'ssh'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                features['service'] = 'https'
            
            # Simple flag approximation
            if packet[TCP].flags == 'S':
                features['flag'] = 'S0' # SYN sent, no reply
            elif packet[TCP].flags == 'R':
                features['flag'] = 'REJ' # Connection rejected
            elif packet[TCP].flags == 'SA':
                features['flag'] = 'S1'
            elif 'F' in str(packet[TCP].flags):
                features['flag'] = 'SF' # Normal close
            
        elif UDP in packet:
            features['protocol_type'] = 'udp'
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                features['service'] = 'domain_u'
                
        elif ICMP in packet:
            features['protocol_type'] = 'icmp'
            features['service'] = 'eco_i' if packet[ICMP].type == 8 else 'ecr_i'
            
    return features

def preprocess_features(features_dict, scaler, model_columns):
    """
    Preprocess the features dictionary to match the model's expected input.
    Mirrors the training pipeline exactly:
      1. Scale numerical columns (all except protocol_type, service, flag)
      2. One-hot encode categorical columns
      3. Align to the model's expected 122 columns
    """
    df = pd.DataFrame([features_dict])
    
    categorical_cols = ['protocol_type', 'service', 'flag']

    # Step 1: Scale numerical columns BEFORE one-hot encoding (mirrors training order).
    # The scaler was fitted on all columns except the 3 categoricals.
    if scaler is not None:
        if hasattr(scaler, 'feature_names_in_'):
            # Scale only the exact columns the scaler was fitted on
            num_cols_to_scale = [c for c in scaler.feature_names_in_ if c in df.columns]
            df[num_cols_to_scale] = scaler.transform(df[num_cols_to_scale])
        else:
            # Fallback: scale everything except categoricals
            num_cols = [c for c in df.columns if c not in categorical_cols]
            df[num_cols] = scaler.transform(df[num_cols])

    # Step 2: One-hot encode categorical variables
    df = pd.get_dummies(df, columns=categorical_cols)
    
    # Step 3: Align to model's expected columns (fill missing one-hot cols with 0, drop extras)
    if model_columns is not None:
        missing_cols = set(model_columns) - set(df.columns)
        for c in missing_cols:
            df[c] = 0
        df = df[model_columns]
        
    return df

