# convert_for_realtime.py
import torch
import numpy as np
import pandas as pd
import os

print("🔄 Converting Kaggle GCN model for real-time intrusion detection...")
print(f"📁 Working directory: {os.getcwd()}")

# List files in current directory
print("📄 Files in directory:")
for file in os.listdir('.'):
    if '.pth' in file:
        print(f"   ✅ {file}")

# Load the main model with weights_only=False for compatibility
try:
    print("🔓 Loading model with compatibility mode...")
    kaggle_model = torch.load('high_perf_hybrid_ids.pth', map_location='cpu', weights_only=False)
    print("✅ Successfully loaded high_perf_hybrid_ids.pth")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit()

# Extract components
model_state = kaggle_model['model_state']
feature_names = kaggle_model['feature_names']
metrics = kaggle_model['metrics']

print("\n📊 Model Performance from Kaggle:")
for metric, value in metrics.items():
    print(f"   {metric}: {value:.4f}")

print(f"\n📋 Features to monitor: {len(feature_names)} features")
print("Sample features:", feature_names[:8])

# Create real-time compatible model
realtime_data = {
    'model_state_dict': model_state,
    'feature_names': feature_names,
    'input_dim': len(feature_names),
    'metrics': metrics,
    'model_architecture': 'AdvancedGCN'
}

# Save for real-time use (removed weights_only from save)
torch.save(realtime_data, 'realtime_gcn_ids.pth')
print("\n✅ Real-time model saved: realtime_gcn_ids.pth")
print("🎉 Ready for real-time network monitoring!")

# Verify the new model can be loaded safely
print("\n🔍 Verifying real-time model can be loaded...")
try:
    test_load = torch.load('realtime_gcn_ids.pth', map_location='cpu')
    print("✅ Real-time model verified and ready for use!")
    print(f"📁 File size: {os.path.getsize('realtime_gcn_ids.pth') / 1024 / 1024:.2f} MB")
except Exception as e:
    print(f"❌ Verification failed: {e}")
