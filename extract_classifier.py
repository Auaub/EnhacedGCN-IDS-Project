# extract_classifier.py
import torch
import os

print("🔧 Extracting classifier from GCN model for real-time use...")

# Load the original model
model_data = torch.load('high_perf_hybrid_ids.pth', map_location='cpu', weights_only=False)

print("📋 Model keys:", list(model_data.keys()))
print("📦 Model state dict keys:", list(model_data['model_state'].keys()))

# Extract only classifier weights
classifier_weights = {}
for key, value in model_data['model_state'].items():
    if 'classifier' in key:
        classifier_weights[key] = value
        print(f"✅ Keeping: {key}")

print(f"\n📊 Found {len(classifier_weights)} classifier parameters")

# Create new model data with only classifier
new_model_data = {
    'model_state_dict': classifier_weights,
    'feature_names': model_data['feature_names'],
    'input_dim': len(model_data['feature_names']),
    'metrics': model_data['metrics']
}

# Save for real-time use
torch.save(new_model_data, 'classifier_only.pth')
print("✅ Classifier-only model saved: classifier_only.pth")
print(f"📁 Input dimension: {new_model_data['input_dim']}")
