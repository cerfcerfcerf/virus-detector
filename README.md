# Intelligent File Risk Analyzer (Heuristic-Based)

## Overview
This project is an offline desktop application written in Python that analyzes files
and estimates their **risk level** using heuristic and rule-based techniques.

The tool does **not** claim to be a traditional antivirus. Instead, it highlights
**suspicious indicators** commonly associated with malware, riskware, cheats,
and obfuscated software, and explains *why* a file may be considered risky.

The main goal of the project is **explainable decision-making**, helping users
understand potential risks before executing unknown files.

---

## Why This Project Matters
Many users download files from the internet (executables, scripts, documents)
without knowing whether they are safe. Professional antivirus solutions are often
black-box systems that provide little explanation for their decisions.

This project focuses on:
- transparency instead of certainty
- education instead of automation
- understanding risk signals rather than making absolute claims

Such tools are useful for **students, researchers, and non-technical users**
who want to understand *why* a file may be suspicious.

---

## Key Features
- Offline file analysis (no file uploads, no cloud dependency)
- Binary-safe file handling (raw bytes, no execution)
- Incremental cryptographic hashing (SHA-256, MD5)
- File type detection using magic bytes and extensions
- Entropy-based analysis for packed/encrypted content
- Heuristic rule engine with weighted scoring
- Categorization of findings (malware-like vs riskware/cheat-like behavior)
- Explainable results in plain language
- Responsive GUI with background scanning thread
- Recent files history with quick access
- Exportable scan reports (JSON)
- External validation links (manual verification)

---

## What This Tool Is (and Is Not)

### ✔ What It Is
- A **file risk analyzer**
- A **heuristic inspection tool**
- An **educational and research project**
- A system that highlights suspicious *signals*

### ✘ What It Is Not
- Not a replacement for antivirus software
- Not a signature-based malware detector
- Not a guarantee that a file is safe or unsafe

---

## About False Positives and VirusTotal Differences
This tool may sometimes flag files that appear safe according to VirusTotal,
and sometimes miss files that VirusTotal flags.

This happens because:
- VirusTotal relies on signature databases and reputation
- This project relies on **local heuristics and feature patterns**
- Tools such as game cheats, injectors, cracks, and debuggers often use
  techniques similar to malware (process injection, obfuscation, networking)

As a result, such files are categorized as **riskware** or **cheat-like behavior**
rather than automatically labeled as malicious.

A file that did not visibly harm the system may still contain risky behavior,
and a flagged file is not automatically malicious.

---

## How the System Works (High-Level)
1. The user selects a file to scan.
2. The file is opened in binary mode and never executed.
3. Cryptographic hashes are calculated incrementally.
4. File type is identified using magic bytes and extension comparison.
5. Features are extracted:
   - entropy
   - printable strings
   - structural metadata
6. Heuristic detection rules are applied.
7. A weighted risk score is calculated.
8. Results are presented with explanations and safe next steps.

---

## Technologies Used
- Python 3.12
- PyQt5 (desktop GUI)
- Multithreading (QThread)
- Standard cryptography and binary analysis techniques

---

## Installation and Usage

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python src/detector.py
