# EnhacedGCN-IDS-Project
Enhanced GCN IDS Project
Overview

This project implements an Intrusion Detection System (IDS) using a Graph Convolutional Network (GCN).
The model has been enhanced by:

Using L1 distance instead of L2 for better feature representation.

Adding a fuzzy KNN classifier to improve detection performance.

The system has been tested on real-time simulation data and shows improved detection accuracy compared to the baseline.

Dataset

The project uses the UNSW-NB15 dataset.

Features include network traffic, connection types, and payload information.

Classes include Normal and multiple attack types.

Project Structure
GCN_IDS_clean/
│
├─ best_gcn_model.pth           # Trained GCN model
├─ classifier_only.pth          # Trained fuzzy KNN classifier
├─ high_perf_hybrid_ids.pth     # Combined model checkpoint
├─ realtime_gcn_ids.pth         # Model for real-time detection
├─ realtime_ids.py              # Script for real-time IDS simulation
├─ convert_for_realtime.py      # Helper to convert model for real-time usage
├─ extract_classifier.py        # Script to extract classifier outputs
├─ README.md                    # This file
├─ LICENSE                      # License for the project
└─ requirements.txt             # Python dependencies (to be generated)

Installation

Clone the repository:

git clone https://github.com/Auaub/EnhacedGCN-IDS-Project.git
cd EnhacedGCN-IDS-Project


Create a virtual environment:

python -m venv gcn-env
source gcn-env/bin/activate   # On Windows use: gcn-env\Scripts\activate


Install dependencies:

pip install -r requirements.txt

Usage

To run the real-time IDS simulation:

python realtime_ids.py


To convert models for real-time use:

python convert_for_realtime.py


To extract classifier outputs:

python extract_classifier.py

Features

Graph-based feature extraction using GCN

Improved distance metric with L1 norm

Fuzzy KNN classifier for better attack detection

Real-time simulation support
