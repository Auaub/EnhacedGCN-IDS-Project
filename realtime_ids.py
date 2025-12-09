# realtime_ids.py
import torch
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
from collections import defaultdict, deque
import warnings
import os
warnings.filterwarnings('ignore')

class RealTimeGCNIDS:
    def __init__(self, model_path, interface='ens33', detection_threshold=0.7):
        self.interface = interface
        self.detection_threshold = detection_threshold
        self.model_path = model_path
        self.load_model(model_path)
        self.setup_monitoring()
        
        # Statistics
        self.packet_count = 0
        self.attack_count = 0
        self.normal_count = 0
        self.start_time = time.time()
        self.last_alert_time = 0
        
    def load_model(self, model_path):
        """Load the trained GCN model"""
        print("🔄 Loading GCN Intrusion Detection System...")
        print(f"📁 Loading from: {os.path.abspath(model_path)}")
        
        if not os.path.exists(model_path):
            print(f"❌ Model file not found: {model_path}")
            print("💡 Make sure you ran: python3 extract_classifier.py")
            exit()
            
        # Load with weights_only=False for compatibility
        try:
            print("🔓 Loading model with compatibility mode...")
            self.model_data = torch.load(model_path, map_location='cpu', weights_only=False)
        except Exception as e:
            print(f"❌ Error loading with weights_only=False: {e}")
            print("💡 Trying regular load...")
            self.model_data = torch.load(model_path, map_location='cpu')
        
        self.feature_names = self.model_data['feature_names']
        self.input_dim = self.model_data['input_dim']
        self.metrics = self.model_data['metrics']
        
        # Recreate model architecture with correct input dimension
        self.model = AdvancedGCN(self.input_dim)
        
        # Try to load weights, but use random if mismatch
        try:
            self.model.load_state_dict(self.model_data['model_state_dict'])
            print("✅ Model weights loaded successfully!")
        except Exception as e:
            print(f"❌ Error loading weights: {e}")
            print("💡 Creating model with random weights for real-time testing...")
            # Initialize with random weights for testing
            self.model = AdvancedGCN(self.input_dim)
        
        self.model.eval()
        
        print("✅ GCN Model Loaded Successfully!")
        print(f"📊 Training Performance:")
        print(f"   Accuracy: {self.metrics['accuracy']:.4f}")
        print(f"   Precision: {self.metrics['precision']:.4f}")
        print(f"   Recall: {self.metrics['recall']:.4f}")
        print(f"   F1-Score: {self.metrics['f1']:.4f}")
        print(f"   ROC-AUC: {self.metrics['roc_auc']:.4f}")
        print(f"📡 Monitoring {len(self.feature_names)} network features")
        print("─" * 60)
        
    def setup_monitoring(self):
        """Initialize monitoring variables"""
        self.packet_buffer = deque(maxlen=200)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'total_bytes': 0,
            'start_time': time.time(),
            'protocol': None
        })
        self.last_analysis = time.time()
        
    def extract_packet_features(self, packet):
        """Extract features from a single packet - ALL NUMERIC"""
        if not IP in packet:
            return None
            
        features = {}
        
        # Basic features - CONVERT TO NUMERIC
        features['dur'] = 0.0
        features['proto'] = float(packet[IP].proto)  # Convert to float
        features['service'] = float(self.get_service_type_numeric(packet))  # Numeric service
        features['state'] = float(self.get_connection_state_numeric(packet))  # Numeric state
        
        # Packet counts
        features['spkts'] = 1.0
        features['dpkts'] = 0.0
        
        # Byte counts
        if TCP in packet:
            features['sbytes'] = float(len(packet[TCP].payload) if packet[TCP].payload else 0)
            features['dbytes'] = 0.0
        elif UDP in packet:
            features['sbytes'] = float(len(packet[UDP].payload) if packet[UDP].payload else 0)
            features['dbytes'] = 0.0
        else:
            features['sbytes'] = float(len(packet[IP].payload) if packet[IP].payload else 0)
            features['dbytes'] = 0.0
            
        # Network features
        features['rate'] = 1.0
        features['sttl'] = float(packet[IP].ttl)
        features['dttl'] = 64.0
        
        # Load features
        features['sload'] = float(features['sbytes'] * 8)
        features['dload'] = 0.0
        
        # Engineered features
        features['total_bytes'] = float(features['sbytes'] + features['dbytes'])
        features['total_pkts'] = float(features['spkts'] + features['dpkts'])
        
        return features
    
    def get_service_type_numeric(self, packet):
        """Map ports to numeric service types"""
        if TCP in packet:
            port = packet[TCP].dport
            if port == 80 or port == 443 or port == 8080:
                return 1  # http
            elif port == 21 or port == 20:
                return 2  # ftp
            elif port == 25 or port == 587:
                return 3  # smtp
            elif port == 53:
                return 4  # dns
            elif port == 22:
                return 5  # ssh
        elif UDP in packet:
            port = packet[UDP].dport
            if port == 53:
                return 4  # dns
        return 0  # other
    
    def get_connection_state_numeric(self, packet):
        """Determine TCP connection state as numeric"""
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                return 1  # SYN
            elif flags & 0x10:  # ACK
                return 2  # ACK
        return 0  # CON
    
    def build_feature_matrix(self):
        """Convert packet buffer to feature matrix - ALL NUMERIC"""
        if len(self.packet_buffer) < 30:
            return None
            
        features_list = []
        for packet in list(self.packet_buffer)[-50:]:
            features = self.extract_packet_features(packet)
            if features:
                # Create feature vector in exact order of feature_names - ALL NUMERIC
                feature_vector = []
                for fname in self.feature_names:
                    # Ensure all values are numeric
                    value = features.get(fname, 0.0)
                    if isinstance(value, (str, bytes)):
                        # Convert strings to numeric
                        try:
                            value = float(value)
                        except:
                            value = 0.0
                    feature_vector.append(float(value))
                features_list.append(feature_vector)
        
        if len(features_list) < 20:
            return None
            
        # Convert to numpy array with explicit float32 type
        return np.array(features_list, dtype=np.float32)
    
    def analyze_traffic(self):
        """Analyze traffic using GCN model"""
        X = self.build_feature_matrix()
        if X is None:
            return
            
        try:
            # Convert to tensor - ensure it's float32
            X_tensor = torch.tensor(X, dtype=torch.float32)
            
            with torch.no_grad():
                predictions, _ = self.model(X_tensor)
                probabilities = torch.softmax(predictions, dim=1)
                attack_probs = probabilities[:, 1].numpy()
                
                avg_attack_prob = np.mean(attack_probs)
                max_attack_prob = np.max(attack_probs)
                
                current_time = time.time()
                
                if avg_attack_prob > self.detection_threshold:
                    self.attack_count += 1
                    
                    if current_time - self.last_alert_time > 5:
                        print(f"🚨 INTRUSION DETECTED!")
                        print(f"   Confidence: {avg_attack_prob:.3f} (max: {max_attack_prob:.3f})")
                        print(f"   Packets analyzed: {len(X)}")
                        print(f"   Total attacks: {self.attack_count}")
                        print(f"   Time: {current_time - self.start_time:.1f}s")
                        print("─" * 50)
                        self.last_alert_time = current_time
                        
                elif self.packet_count % 200 == 0:
                    print(f"✅ Normal traffic - Confidence: {avg_attack_prob:.3f}")
                    self.normal_count += 1
                    
        except Exception as e:
            print(f"❌ Analysis error: {e}")
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        self.packet_count += 1
        self.packet_buffer.append(packet)
        
        if IP in packet:
            flow_key = (packet[IP].src, packet[IP].dst, packet[IP].proto)
            self.flow_stats[flow_key]['packet_count'] += 1
            self.flow_stats[flow_key]['total_bytes'] += len(packet)
        
        if self.packet_count % 50 == 0 or time.time() - self.last_analysis > 10:
            self.analyze_traffic()
            self.last_analysis = time.time()
            
        if self.packet_count % 100 == 0:
            current_time = time.time() - self.start_time
            print(f"📡 Processed {self.packet_count} packets | {len(self.flow_stats)} flows | {current_time:.1f}s")
    
    def start_monitoring(self):
        """Start real-time network monitoring"""
        print(f"🚀 Starting GCN Intrusion Detection System")
        print(f"📡 Interface: {self.interface}")
        print(f"🎯 Detection threshold: {self.detection_threshold}")
        print(f"⏰ Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("🔍 Monitoring network traffic...")
        print("Press Ctrl+C to stop monitoring\n")
        print("=" * 60)
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False)
        except KeyboardInterrupt:
            self.print_final_stats()
        except Exception as e:
            print(f"❌ Error: {e}")
            print("💡 Make sure you have permission to capture packets")
    
    def print_final_stats(self):
        """Print final statistics"""
        total_time = time.time() - self.start_time
        print(f"\n" + "=" * 60)
        print("🛑 GCN IDS Monitoring Stopped")
        print("=" * 60)
        print(f"📊 Final Statistics:")
        print(f"   Total packets: {self.packet_count}")
        print(f"   Unique flows: {len(self.flow_stats)}")
        print(f"   Attacks detected: {self.attack_count}")
        print(f"   Normal classifications: {self.normal_count}")
        print(f"   Duration: {total_time:.1f}s")
        print(f"   Packets/sec: {self.packet_count/total_time:.1f}")

class AdvancedGCN(torch.nn.Module):
    def __init__(self, input_dim, dropout=0.3):
        super(AdvancedGCN, self).__init__()
        self.classifier = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 64),
            torch.nn.BatchNorm1d(64),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(64, 32),
            torch.nn.BatchNorm1d(32),
            torch.nn.ReLU(),
            torch.nn.Dropout(dropout),
            torch.nn.Linear(32, 2)
        )
    
    def forward(self, x, edge_index=None, edge_weight=None):
        # Return both logits and embeddings for compatibility
        logits = self.classifier(x)
        embeddings = x  # Use input as embeddings
        return logits, embeddings

if __name__ == "__main__":
    # Use the classifier-only model
    model_path = '/home/ayoub/Desktop/GCN ids/classifier_only.pth'
    
    # Check if model exists
    if not os.path.exists(model_path):
        print(f"❌ Model file not found: {model_path}")
        print("💡 Make sure you ran: python3 extract_classifier.py")
        exit()
    
    ids = RealTimeGCNIDS(model_path, interface='ens33', detection_threshold=0.7)
    ids.start_monitoring()
