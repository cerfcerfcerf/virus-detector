# File Risk Analyzer (Heuristic-Based)

## Overview
**File Risk Analyzer** is an offline desktop application written in Python that
inspects files and estimates their **risk level** using heuristic analysis.

The application does **not** claim to be an antivirus or malware detector.
Instead, it identifies **suspicious indicators** commonly associated with malware,
riskware, cheats, injectors, and obfuscated software, and explains *why* a file
may be risky.

The main focus of this project is **explainability**, transparency, and safe
decision support.

---

## Purpose and Motivation
Many users download executables, scripts, and documents without understanding
the potential risks. Traditional antivirus solutions often provide a simple
“safe / unsafe” verdict without explanation.

This project was created to:
- show *which signals* make a file suspicious
- avoid black-box decision making
- support learning and research
- help users decide what to do **before executing a file**

---

## What This Tool Is
- A **heuristic file risk analyzer**
- An **offline inspection tool**
- An **educational and research project**
- A system that highlights **risk signals**, not absolute truth

## What This Tool Is Not
- Not an antivirus
- Not a signature-based malware scanner
- Not a guarantee that a file is safe or malicious

---

## Key Features
- Offline analysis (no file uploads, no cloud services)
- Binary-safe file handling (files are never executed)
- Incremental cryptographic hashing:
  - SHA-256
  - MD5
- File type identification using:
  - magic bytes
  - file extension comparison
- Entropy analysis to detect packed or encrypted content
- Printable string extraction
- Heuristic rule engine with weighted scoring
- Risk level classification:
  - Low
  - Medium
  - High
- Human-readable explanations for each finding
- Recommendations based on risk level
- Responsive GUI (background scanning thread)
- Recent files list with quick access
- Open file location directly in Windows Explorer
- Exportable scan reports (JSON)
- Manual external validation via VirusTotal link

---

## About Risk Scores and False Positives
This application uses **heuristics**, not signatures or reputation databases.

Because of this:
- Some files may be flagged as risky even if they are not actively malicious
- Tools such as game cheats, injectors, debuggers, and cracks often trigger
  warnings because they use techniques similar to malware
- Some malicious files may appear safe if they lack obvious indicators

Differences between this tool and VirusTotal are expected because:
- VirusTotal uses antivirus signatures and reputation
- This tool relies on local feature analysis only

A file that did not visibly harm the system may still contain risky behavior.
A flagged file is **not automatically malware**.

---

## How the System Works (High-Level)
1. User selects a file or drags it into the application
2. File is opened in binary mode and never executed
3. Hashes are calculated incrementally
4. File type is determined using magic bytes and extensions
5. Content is read in a size-aware manner
6. Features are extracted:
   - entropy
   - printable strings
   - structural metadata
7. Heuristic rules are applied
8. A weighted risk score is calculated
9. Results are presented with explanations and recommendations

---

## Advanced Mode
When enabled, the analyzer additionally:
- attempts limited decoding of encoded-looking strings
- performs lightweight executable metadata checks
- applies extra heuristic rules

Advanced mode is optional and increases analysis depth.

---

## Technologies Used
- Python 3.12
- PyQt5 (desktop GUI)
- Multithreading (QThread)
- Standard Python libraries for cryptography and binary analysis

---

## Installation and Usage

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install PyQt5
python detector.py
