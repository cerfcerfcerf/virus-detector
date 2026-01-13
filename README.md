# virus-detector
# Intelligent Malware Detector (Heuristic-Based)

## Overview
This project is an offline desktop application written in Python that analyzes files
and estimates their risk level using heuristic and rule-based techniques.

The system extracts file features such as hashes, entropy, file type (magic bytes),
and suspicious strings, and produces an explainable risk score with human-readable reasons.

The application is designed for educational and research purposes and does not replace
professional antivirus software.

## Key Features
- Offline file analysis (no cloud upload)
- Incremental cryptographic hashing (SHA-256, MD5)
- File type detection using magic bytes and extensions
- Entropy-based analysis
- Heuristic rule engine with weighted scoring
- Explainable results for non-technical users
- Responsive GUI (background scanning thread)
- Optional advanced analysis mode
- Exportable scan reports (JSON)

## Technologies Used
- Python 3.12
- PyQt5 (GUI)
- Multithreading (QThread)
- Standard cryptography and binary analysis techniques

## How It Works (High-Level)
1. The user selects a file to scan.
2. The file is read as raw bytes (binary-safe).
3. Features are extracted (hashes, entropy, strings, metadata).
4. Detection rules are applied with weighted scoring.
5. A final risk level (Low / Medium / High) is produced with explanations.
6. The user is advised on safe next steps.

## Installation
```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python src/detector.py
