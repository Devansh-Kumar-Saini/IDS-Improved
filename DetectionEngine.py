from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.signature_rules = self.load_signature_rules()
        self.is_trained = False

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50  and
                    features['packet_rate'] > 20
                )
                
            },
            'nmap_stealth_scan': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN
                    features['window_size'] == 1024  # Common Nmap window size
                )
            },
            'nmap_xmas_scan': {
                'condition': lambda features: (
                    features['tcp_flags'] == 0b00101001  # FIN, URG, PSH
                )
            },
            'nmap_null_scan': {
                'condition': lambda features: (
                    features['tcp_flags'] == 0  # No flags set
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        if len(normal_traffic_data) > 10:
            self.anomaly_detector.fit(normal_traffic_data)
            self.is_trained = True

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        if self.is_trained:
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate'],
                features['window_size']
            ]])
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': anomaly_score,
                    'confidence': min(1.0, abs(anomaly_score))
                })

        return threats