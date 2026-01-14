import sys, os, time, math, json, hashlib, re, base64, webbrowser, subprocess
from dataclasses import dataclass
from datetime import datetime

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt, QSettings
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QProgressBar, QTextEdit, QCheckBox, QMessageBox, QFrame,
    QSplitter, QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView,
    QTabWidget, QListWidget, QListWidgetItem, QLineEdit, QSizePolicy
)


@dataclass
class Finding:
    title: str
    severity: str
    weight: int
    explanation: str
    evidence: str


class ScannerWorker(QObject):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)

    def __init__(self, path: str, advanced: bool = False):
        super().__init__()
        self.path = path
        self.advanced = advanced

        self.entropy_high = 7.23
        self.large_file_warn = 48 * 1024 * 1024
        self.full_read_limit = 20 * 1024 * 1024
        self.sample_read = 2 * 1024 * 1024

        self.sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

        self.type_rules = {
            "script": [
                (b"invoke-webrequest", "High", 26, "Looks like it can download content from the internet."),
                (b"iex", "High", 18, "IEX is often used to execute downloaded code."),
                (b"frombase64string", "Medium", 16, "Base64 decoding appears in obfuscated scripts."),
                (b"reg add", "Medium", 12, "Registry modification can be persistence-related."),
                (b"schtasks", "High", 18, "Task scheduler usage can be persistence-related."),
            ],
            "exe": [
                (b"powershell", "Medium", 14, "Executable contains PowerShell-related text."),
                (b"cmd.exe", "Medium", 12, "Executable references command shell."),
                (b"rundll32", "Medium", 13, "Executable references rundll32 (often used for LOLBins)."),
                (b"virtualalloc", "High", 18, "Memory allocation APIs sometimes appear in injectors/packers."),
                (b"writeprocessmemory", "High", 22, "Process memory writing can be used by malware."),
            ],
            "zip": [
                (b"vbaproject.bin", "High", 22, "Office macro container name appears (possible macros)."),
                (b"word/_rels", "Low", 6, "Office doc structure detected (not bad by itself)."),
            ],
            "pdf": [
                (b"/js", "Medium", 14, "PDF contains JavaScript markers (can be abused)."),
                (b"/openaction", "Medium", 12, "PDF auto-action markers appear."),
            ],
            "unknown": [
                (b"powershell", "Medium", 14, "Contains PowerShell-related text."),
                (b"http://", "Medium", 10, "Contains URL text."),
                (b"https://", "Medium", 10, "Contains URL text."),
            ],
        }

        self.generic_tokens = [
            b"powershell", b"-enc", b"cmd.exe", b"rundll32", b"reg add", b"schtasks",
            b"http://", b"https://", b"wget", b"curl", b"pastebin", b"discordapp",
            b"token", b"stealer", b"keylogger"
        ]

        self.band_low = 39
        self.band_med = 69

    def run(self):
        try:
            report = self.scan_file(self.path)
            self.finished.emit(report)
        except Exception as e:
            self.finished.emit({"error": f"{type(e).__name__}: {str(e)}", "path": self.path})

    def scan_file(self, path: str) -> dict:
        t0 = time.time()
        self.progress.emit(2, "Opening file (binary-safe)")
        size = os.path.getsize(path)
        filename = os.path.basename(path)

        warnings = []
        if size >= self.large_file_warn:
            warnings.append(f"Large file ({size} bytes). Scan uses sampling to avoid heavy memory use.")

        self.progress.emit(8, "Reading header (magic bytes)")
        with open(path, "rb") as f:
            head = f.read(4096)

        self.progress.emit(14, "Classifying file type")
        kind, kind_reason = self.classify(path, head)

        self.progress.emit(24, "Hashing (incremental)")
        sha256, md5 = self.stream_hashes(path)

        self.progress.emit(36, "Reading content (size-aware)")
        data = self.read_content_size_aware(path, size)

        self.progress.emit(48, "Entropy measurement")
        ent = self.entropy(data)

        self.progress.emit(58, "Extracting printable strings")
        big_text = self.extract_printable_strings(data)
        lower_text = big_text.lower()

        self.progress.emit(68, "Applying detections + scoring")
        findings = []
        score = 0

        if kind == "exe":
            f = Finding(
                title="Windows executable",
                severity="Low",
                weight=10,
                explanation="Executables can run code. Treat unknown executables as higher risk than documents.",
                evidence="MZ header / executable signature"
            )
            findings.append(f)
            score += f.weight

        if ent > self.entropy_high:
            w = 21
            sev = "Medium" if ent < 7.65 else "High"
            findings.append(Finding(
                title="High entropy content",
                severity=sev,
                weight=w,
                explanation="High entropy often means packing/encryption, which can hide the real content.",
                evidence=f"entropy={ent:.2f} threshold={self.entropy_high}"
            ))
            score += w

        hits = [tok for tok in self.generic_tokens if tok in lower_text]
        if len(hits) >= 2:
            w = min(35, 10 + 5 * len(hits))
            findings.append(Finding(
                title="Suspicious command/network strings",
                severity="High",
                weight=w,
                explanation="Multiple strings commonly used in malware or downloaders appear.",
                evidence=f"hits={len(hits)}"
            ))
            score += w
        elif len(hits) == 1:
            findings.append(Finding(
                title="One suspicious string present",
                severity="Info",
                weight=5,
                explanation="A single suspicious string can be noise, but it’s worth a second look.",
                evidence=f"hit={hits[0].decode(errors='ignore')}"
            ))
            score += 5

        for pat, sev, w, expl in (self.type_rules.get(kind, []) + self.type_rules.get("unknown", [])):
            if pat in lower_text:
                findings.append(Finding(
                    title=f"Pattern: {pat.decode(errors='ignore')}",
                    severity=sev,
                    weight=w,
                    explanation=expl,
                    evidence="match in extracted strings"
                ))
                score += w

        decoded_snips = []
        pe_meta = {}
        if self.advanced:
            self.progress.emit(78, "Advanced: limited decode attempts")
            decoded_snips = self.try_decode_base64ish(big_text)

            if decoded_snips:
                for i, s in enumerate(decoded_snips[:4]):
                    sl = s.lower()
                    dhits = [tok for tok in self.generic_tokens if tok in sl]
                    if len(dhits) >= 2:
                        w = 10
                        findings.append(Finding(
                            title="Decoded snippet contains suspicious strings",
                            severity="Medium",
                            weight=w,
                            explanation="A decoded-looking substring contains multiple suspicious tokens.",
                            evidence=f"decoded_hits={len(dhits)} snippet#{i}"
                        ))
                        score += w

            if kind == "exe":
                self.progress.emit(86, "Advanced: light executable metadata")
                pe_meta, pe_findings = self.light_pe_checks(path)
                for f in pe_findings:
                    findings.append(f)
                    score += f.weight

        score = max(0, min(100, score))

        if score >= self.band_med:
            risk = "High"
        elif score >= self.band_low:
            risk = "Medium"
        else:
            risk = "Low"

        findings.sort(key=lambda x: (self.sev_rank.get(x.severity, 9), -x.weight))

        self.progress.emit(94, "Preparing report")
        recs = self.recommend(risk)
        hooks = {
            "virustotal_sha256": f"https://www.virustotal.com/gui/search/{sha256}",
        }

        elapsed = round(time.time() - t0, 3)
        self.progress.emit(100, "Done")

        return {
            "path": path,
            "filename": filename,
            "size_bytes": size,
            "type_guess": kind,
            "type_reason": kind_reason,
            "sha256": sha256,
            "md5": md5,
            "entropy_sample": round(ent, 3),
            "risk_score": score,
            "risk_level": risk,
            "findings": [f.__dict__ for f in findings],
            "warnings": warnings,
            "advanced": {
                "enabled": self.advanced,
                "decoded_snippets_count": len(decoded_snips),
                "pe_meta": pe_meta,
            },
            "external_validation": hooks,
            "recommendations": recs,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "elapsed_seconds": elapsed,
            "note": "Heuristic tool. It can be wrong. Do not execute unknown files. Verify suspicious files with trusted security tools."
        }

    def classify(self, path: str, head: bytes):
        ext = os.path.splitext(path)[1].lower()

        if head.startswith(b"MZ"):
            return "exe", "magic=MZ"
        if head.startswith(b"\x7FELF"):
            return "elf", "magic=ELF"
        if head.startswith(b"%PDF"):
            return "pdf", "magic=%PDF"
        if head.startswith(b"\x50\x4B\x03\x04"):
            if ext in [".docx", ".xlsx", ".pptx"]:
                return "zip", f"magic=ZIP (office ext {ext})"
            return "zip", "magic=ZIP"
        if ext in [".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"]:
            return "script", f"ext={ext}"
        if ext in [".exe", ".dll"]:
            return "exe", f"ext={ext} (no magic match)"
        if ext in [".pdf"]:
            return "pdf", f"ext={ext} (no magic match)"
        if ext in [".zip", ".jar"]:
            return "zip", f"ext={ext} (no magic match)"
        return "unknown", f"ext={ext or '(none)'} + magic=unknown"

    def stream_hashes(self, path: str):
        sha = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                sha.update(chunk)
                md5.update(chunk)
        return sha.hexdigest(), md5.hexdigest()

    def read_content_size_aware(self, path: str, size: int) -> bytes:
        if size <= self.full_read_limit:
            with open(path, "rb") as f:
                return f.read()
        with open(path, "rb") as f:
            return f.read(self.sample_read)

    def entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    def extract_printable_strings(self, data: bytes) -> bytes:
        out = []
        cur = bytearray()
        for b in data:
            if 32 <= b <= 126:
                cur.append(b)
            else:
                if len(cur) >= 5:
                    out.append(bytes(cur))
                cur.clear()
        if len(cur) >= 5:
            out.append(bytes(cur))
        return b"\n".join(out)

    def try_decode_base64ish(self, big_text: bytes):
        decoded = []
        for m in re.finditer(rb"[A-Za-z0-9+/=]{80,}", big_text):
            chunk = m.group(0)
            if b"=" not in chunk and (len(chunk) % 4 != 0):
                continue
            if len(decoded) >= 6:
                break
            try:
                raw = base64.b64decode(chunk[:3000], validate=False)
                if raw and sum(1 for b in raw[:200] if 32 <= b <= 126) >= 40:
                    decoded.append(raw)
            except Exception:
                continue
        return decoded

    def light_pe_checks(self, path: str):
        meta = {}
        findings = []
        try:
            with open(path, "rb") as f:
                mz = f.read(64)
                if not mz.startswith(b"MZ"):
                    return meta, findings
                e_lfanew = int.from_bytes(mz[0x3C:0x40], "little", signed=False)
                f.seek(e_lfanew, 0)
                sig = f.read(4)
                if sig != b"PE\x00\x00":
                    findings.append(Finding(
                        title="PE signature mismatch",
                        severity="High",
                        weight=18,
                        explanation="Executable header looks unusual (PE signature mismatch).",
                        evidence=f"sig={sig!r}"
                    ))
                    return meta, findings

                file_header = f.read(20)
                if len(file_header) < 20:
                    return meta, findings

                ts = int.from_bytes(file_header[4:8], "little", signed=False)
                meta["timestamp_raw"] = ts
                if ts != 0:
                    try:
                        dt = datetime.utcfromtimestamp(ts)
                        meta["timestamp_utc"] = dt.isoformat(timespec="seconds") + "Z"
                        if dt.year < 2000 or dt.year > (datetime.utcnow().year + 1):
                            findings.append(Finding(
                                title="Unusual build timestamp",
                                severity="Medium",
                                weight=12,
                                explanation="The PE build timestamp is unusual. Sometimes packers spoof timestamps.",
                                evidence=f"timestamp={meta['timestamp_utc']}"
                            ))
                    except Exception:
                        pass
                else:
                    findings.append(Finding(
                        title="Zeroed PE timestamp",
                        severity="Low",
                        weight=7,
                        explanation="Timestamp is zero. Not always bad, but sometimes used by packed malware.",
                        evidence="timestamp=0"
                    ))

                num_sections = int.from_bytes(file_header[2:4], "little", signed=False)
                meta["num_sections"] = num_sections
                opt_size = int.from_bytes(file_header[16:18], "little", signed=False)
                f.seek(opt_size, 1)

                section_names = []
                for _ in range(min(num_sections, 12)):
                    sec = f.read(40)
                    if len(sec) < 40:
                        break
                    name = sec[0:8].split(b"\x00", 1)[0].decode(errors="ignore")
                    if name:
                        section_names.append(name)

                meta["section_names"] = section_names
                weird = [n for n in section_names if n.lower() in ("upx0", "upx1", "aspack", ".packed", "petite")]
                if weird:
                    findings.append(Finding(
                        title="Possible packer sections",
                        severity="High",
                        weight=20,
                        explanation="Section names suggest the executable may be packed/compressed.",
                        evidence=f"sections={weird}"
                    ))

                if num_sections >= 8 and not weird:
                    findings.append(Finding(
                        title="Many PE sections",
                        severity="Low",
                        weight=6,
                        explanation="Many sections can be normal, but sometimes appear in packed builds.",
                        evidence=f"num_sections={num_sections}"
                    ))

        except Exception as e:
            meta["pe_error"] = f"{type(e).__name__}: {str(e)}"
        return meta, findings

    def recommend(self, risk: str):
        if risk == "High":
            return [
                "Do not run this file.",
                "Scan it with trusted antivirus software.",
                "Verify the SHA256 hash on external services (manual).",
                "Assume unknown downloads are unsafe until proven otherwise."
            ]
        if risk == "Medium":
            return [
                "Be cautious: open only if you trust the source.",
                "Prefer safe viewers / sandboxed environments for documents.",
                "Verify SHA256 hash externally (manual)."
            ]
        return [
            "No strong suspicious signals detected in this scan.",
            "Still use common sense: open files only from trusted sources.",
            "If something feels off, verify using a trusted AV or hash search."
        ]


class DropArea(QFrame):
    dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setObjectName("Card")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.dropped.emit(path)


class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Risk Analyzer (Heuristic)")
        self.resize(1120, 690)

        self.settings = QSettings("InfomatrixProject", "FileRiskAnalyzer")
        self.recent_limit = 12

        self.file_path = None
        self.last_report = None
        self.thread = None
        self.worker = None

        self.setStyleSheet("""
QWidget { font-family: Segoe UI; font-size: 12pt; }
QPushButton { padding: 8px 14px; border-radius: 10px; }
QPushButton:disabled { opacity: 0.5; }
QLineEdit, QTextEdit { border: 1px solid #cfcfcf; border-radius: 10px; padding: 8px; }
QProgressBar { border-radius: 10px; text-align: center; height: 18px; border: 1px solid #cfcfcf; }
QProgressBar::chunk { border-radius: 10px; }
QFrame#Card { border: 1px solid #d9d9d9; border-radius: 16px; padding: 12px; }
QLabel#Title { font-size: 18pt; font-weight: 800; }
QLabel#Subtle { color: #666; }
QLabel#RiskBadge { padding: 10px 14px; border-radius: 18px; font-weight: 900; font-size: 14pt; }
QTableWidget { border-radius: 10px; }
""")

        self.title = QLabel("File Risk Analyzer")
        self.title.setObjectName("Title")
        self.subtitle = QLabel("Offline heuristic-based analysis with explainable signals.")
        self.subtitle.setObjectName("Subtle")

        left_head = QVBoxLayout()
        left_head.addWidget(self.title)
        left_head.addWidget(self.subtitle)

        self.choose_btn = QPushButton("Choose file…")
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setEnabled(False)
        self.advanced_cb = QCheckBox("Advanced mode")

        self.copy_hash_btn = QPushButton("Copy SHA256")
        self.open_loc_btn = QPushButton("Open file location")
        self.export_btn = QPushButton("Export JSON…")
        self.vt_btn = QPushButton("VirusTotal lookup")

        for b in (self.copy_hash_btn, self.open_loc_btn, self.export_btn, self.vt_btn):
            b.setEnabled(False)

        right_actions = QHBoxLayout()
        right_actions.addWidget(self.choose_btn)
        right_actions.addWidget(self.scan_btn)
        right_actions.addSpacing(10)
        right_actions.addWidget(self.advanced_cb)
        right_actions.addStretch(1)
        right_actions.addWidget(self.copy_hash_btn)
        right_actions.addWidget(self.open_loc_btn)
        right_actions.addWidget(self.export_btn)
        right_actions.addWidget(self.vt_btn)

        header = QFrame()
        header.setObjectName("Card")
        header_l = QHBoxLayout()
        header_l.addLayout(left_head, 1)
        header_l.addLayout(right_actions, 2)
        header.setLayout(header_l)

        self.drop = DropArea()
        drop_l = QVBoxLayout()
        self.path_label = QLabel("Drop a file here or click “Choose file…”")
        self.path_label.setWordWrap(True)
        drop_l.addWidget(self.path_label)
        self.drop.setLayout(drop_l)

        self.progress = QProgressBar()
        self.status = QLabel("Idle.")
        self.status.setObjectName("Subtle")

        self.recent_title = QLabel("Recent files")
        self.recent_title.setObjectName("Subtle")
        self.recent_search = QLineEdit()
        self.recent_search.setPlaceholderText("Filter recent files…")
        self.recent_list = QListWidget()
        self.recent_list.setSelectionMode(QAbstractItemView.SingleSelection)

        self.open_recent_loc_btn = QPushButton("Open selected location")
        self.open_recent_loc_btn.setEnabled(True)
        self.clear_recent_btn = QPushButton("Clear")
        self.clear_recent_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        recent_card = QFrame()
        recent_card.setObjectName("Card")
        rv = QVBoxLayout()
        rt = QHBoxLayout()
        rt.addWidget(self.recent_title)
        rt.addStretch(1)
        rt.addWidget(self.clear_recent_btn)
        rv.addLayout(rt)
        rv.addWidget(self.recent_search)
        rv.addWidget(self.recent_list, 1)
        rv.addWidget(self.open_recent_loc_btn)
        recent_card.setLayout(rv)

        self.risk_badge = QLabel("—")
        self.risk_badge.setObjectName("RiskBadge")
        self.score_big = QLabel("Score: —/100")
        self.score_big.setFont(QFont("Segoe UI", 16, QFont.Bold))
        self.meta_small = QLabel("")
        self.meta_small.setWordWrap(True)
        self.meta_small.setObjectName("Subtle")

        summary_card = QFrame()
        summary_card.setObjectName("Card")
        sv = QVBoxLayout()
        sv.addWidget(QLabel("Decision", objectName="Subtle"))
        sv.addWidget(self.risk_badge)
        sv.addWidget(self.score_big)
        sv.addSpacing(8)
        sv.addWidget(QLabel("File info", objectName="Subtle"))
        sv.addWidget(self.meta_small)
        sv.addStretch(1)
        summary_card.setLayout(sv)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Weight", "Title", "Explanation"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        self.reasons = QListWidget()
        self.reco = QTextEdit()
        self.reco.setReadOnly(True)

        summary_tab = QWidget()
        ssv = QVBoxLayout()
        ssv.addWidget(QLabel("Top reasons"))
        ssv.addWidget(self.reasons, 1)
        ssv.addWidget(QLabel("Recommendations"))
        ssv.addWidget(self.reco, 1)
        summary_tab.setLayout(ssv)

        findings_tab = QWidget()
        ftv = QVBoxLayout()
        ftv.addWidget(self.table)
        findings_tab.setLayout(ftv)

        self.raw = QTextEdit()
        self.raw.setReadOnly(True)

        self.tabs = QTabWidget()
        self.tabs.addTab(summary_tab, "Summary")
        self.tabs.addTab(findings_tab, "Findings")
        self.tabs.addTab(self.raw, "Raw report")

        center = QSplitter(Qt.Vertical)
        top_center = QSplitter(Qt.Horizontal)
        top_center.addWidget(summary_card)
        top_center.addWidget(self.tabs)
        top_center.setSizes([320, 740])
        center.addWidget(top_center)
        center.setSizes([520])

        left_panel = QSplitter(Qt.Vertical)
        left_panel.addWidget(recent_card)
        left_panel.setSizes([640])

        main_split = QSplitter(Qt.Horizontal)
        main_split.addWidget(left_panel)
        main_split.addWidget(center)
        main_split.setSizes([320, 800])

        layout = QVBoxLayout()
        layout.addWidget(header)
        layout.addWidget(self.drop)
        layout.addWidget(self.progress)
        layout.addWidget(self.status)
        layout.addWidget(main_split, 1)
        self.setLayout(layout)

        self.set_badge("—")

        self.choose_btn.clicked.connect(self.pick_file)
        self.scan_btn.clicked.connect(self.start_scan)
        self.export_btn.clicked.connect(self.export_json)
        self.vt_btn.clicked.connect(self.open_vt)
        self.drop.dropped.connect(self.set_file)
        self.copy_hash_btn.clicked.connect(self.copy_sha256)
        self.open_loc_btn.clicked.connect(self.open_location)
        self.recent_list.itemActivated.connect(self.open_recent_item)
        self.recent_search.textChanged.connect(self.apply_recent_filter)
        self.clear_recent_btn.clicked.connect(self.clear_recent)
        self.open_recent_loc_btn.clicked.connect(self.open_recent_location)

        self.load_recent()

    def set_badge(self, risk: str):
        if risk == "High":
            self.risk_badge.setText("HIGH")
            self.risk_badge.setStyleSheet("background:#ffebee; color:#b71c1c;")
        elif risk == "Medium":
            self.risk_badge.setText("MEDIUM")
            self.risk_badge.setStyleSheet("background:#fff8e1; color:#f57f17;")
        elif risk == "Low":
            self.risk_badge.setText("LOW")
            self.risk_badge.setStyleSheet("background:#e8f5e9; color:#1b5e20;")
        else:
            self.risk_badge.setText("—")
            self.risk_badge.setStyleSheet("background:#eeeeee; color:#333;")

    def fmt_bytes(self, n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 * 1024 * 1024:
            return f"{n / (1024 * 1024):.1f} MB"
        return f"{n / (1024 * 1024 * 1024):.2f} GB"

    def set_file(self, path: str):
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Not a file", "Please select a valid file.")
            return
        self.file_path = os.path.abspath(path)
        self.path_label.setText(self.file_path)
        self.scan_btn.setEnabled(True)
        self.status.setText("Ready.")
        self.progress.setValue(0)
        self.clear_report_ui()

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to scan")
        if path:
            self.set_file(path)

    def clear_report_ui(self):
        self.last_report = None
        for b in (self.copy_hash_btn, self.open_loc_btn, self.export_btn, self.vt_btn):
            b.setEnabled(False)
        self.set_badge("—")
        self.score_big.setText("Score: —/100")
        self.meta_small.setText("")
        self.reasons.clear()
        self.reco.clear()
        self.raw.clear()
        self.table.setRowCount(0)

    def start_scan(self):
        if not self.file_path:
            return

        self.clear_report_ui()
        self.scan_btn.setEnabled(False)
        self.choose_btn.setEnabled(False)
        self.status.setText("Starting…")
        self.progress.setValue(1)

        self.thread = QThread()
        self.worker = ScannerWorker(self.file_path, advanced=self.advanced_cb.isChecked())
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    def on_progress(self, pct: int, msg: str):
        self.progress.setValue(pct)
        self.status.setText(msg)

    def on_finished(self, report: dict):
        self.scan_btn.setEnabled(True)
        self.choose_btn.setEnabled(True)
        self.last_report = report

        self.export_btn.setEnabled(True)

        if "error" in report:
            self.set_badge("High")
            self.score_big.setText("Score: —/100")
            self.meta_small.setText("Scan produced an error. Partial report available.")
            self.raw.setText(json.dumps(report, indent=2))
            self.status.setText("Finished with error.")
            return

        risk = report.get("risk_level", "—")
        score = report.get("risk_score", "—")
        self.set_badge(risk)
        self.score_big.setText(f"Score: {score}/100")

        meta = (
            f"Name: {report.get('filename')}\n"
            f"Type: {report.get('type_guess')} ({report.get('type_reason')})\n"
            f"Size: {self.fmt_bytes(int(report.get('size_bytes', 0)))}\n"
            f"SHA256: {report.get('sha256')}\n"
            f"Entropy(sample): {report.get('entropy_sample')}\n"
            f"Advanced: {report.get('advanced', {}).get('enabled')}\n"
            f"Time: {report.get('elapsed_seconds')}s"
        )
        self.meta_small.setText(meta)

        findings = report.get("findings", [])
        self.table.setRowCount(len(findings))
        for r, f in enumerate(findings):
            self.table.setItem(r, 0, QTableWidgetItem(str(f.get("severity", ""))))
            self.table.setItem(r, 1, QTableWidgetItem(str(f.get("weight", ""))))
            self.table.setItem(r, 2, QTableWidgetItem(str(f.get("title", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(f.get("explanation", ""))))

        self.reasons.clear()
        top = findings[:6]
        if not top:
            self.reasons.addItem("No strong signals detected in this scan.")
        else:
            for f in top:
                self.reasons.addItem(f"{f.get('severity')} (+{f.get('weight')}): {f.get('title')}")

        recs = report.get("recommendations", [])
        self.reco.setText("\n".join([f"• {r}" for r in recs]) if recs else "• No recommendations.")

        self.raw.setText(json.dumps(report, indent=2))

        for b in (self.copy_hash_btn, self.open_loc_btn, self.export_btn, self.vt_btn):
            b.setEnabled(True)

        self.status.setText("Done.")
        self.add_recent(self.file_path)

    def copy_sha256(self):
        if not self.last_report:
            return
        h = self.last_report.get("sha256")
        if not h:
            return
        QApplication.clipboard().setText(h)
        self.status.setText("SHA256 copied to clipboard.")

    def open_location(self):
        path = self.file_path
        if not path:
            return
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            QMessageBox.information(self, "Missing file", "File not found on disk.")
            return
        try:
            subprocess.run(["explorer.exe", f"/select,{path}"], check=False)
        except Exception:
            try:
                os.startfile(os.path.dirname(path))
            except Exception:
                pass

    def open_recent_location(self):
        item = self.recent_list.currentItem()
        if not item:
            return
        path = item.data(Qt.UserRole)
        if not path:
            return
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            QMessageBox.information(self, "Missing file", "This file no longer exists on disk.")
            return
        try:
            subprocess.run(["explorer.exe", f"/select,{path}"], check=False)
        except Exception:
            try:
                os.startfile(os.path.dirname(path))
            except Exception:
                pass

    def export_json(self):
        if not self.last_report:
            return
        default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Export report as JSON", default_name, "JSON files (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.last_report, f, indent=2, ensure_ascii=False)
            self.status.setText("Exported report.")
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    def open_vt(self):
        if not self.last_report:
            return
        url = self.last_report.get("external_validation", {}).get("virustotal_sha256")
        if url:
            webbrowser.open(url)

    def load_recent(self):
        raw = self.settings.value("recent_files", [])
        if not isinstance(raw, list):
            raw = []
        self.recent_files = [p for p in raw if isinstance(p, str)]
        self.refresh_recent()

    def save_recent(self):
        self.settings.setValue("recent_files", self.recent_files)

    def refresh_recent(self):
        self.recent_list.clear()
        for p in self.recent_files:
            name = os.path.basename(p)
            item = QListWidgetItem(name)
            item.setToolTip(p)
            item.setData(Qt.UserRole, p)
            self.recent_list.addItem(item)
        self.apply_recent_filter(self.recent_search.text())

    def apply_recent_filter(self, text: str):
        t = (text or "").strip().lower()
        for i in range(self.recent_list.count()):
            item = self.recent_list.item(i)
            p = (item.data(Qt.UserRole) or "")
            name = os.path.basename(p).lower()
            show = (t in name) or (t in p.lower())
            item.setHidden(not show)

    def add_recent(self, path: str):
        if not path:
            return
        path = os.path.abspath(path)
        if path in self.recent_files:
            self.recent_files.remove(path)
        self.recent_files.insert(0, path)
        self.recent_files = self.recent_files[:self.recent_limit]
        self.save_recent()
        self.refresh_recent()

    def clear_recent(self):
        self.recent_files = []
        self.save_recent()
        self.refresh_recent()
        self.status.setText("Recent files cleared.")

    def open_recent_item(self, item: QListWidgetItem):
        path = item.data(Qt.UserRole)
        if path and os.path.isfile(path):
            self.set_file(path)
            self.add_recent(path)
        else:
            QMessageBox.information(self, "Missing file", "This file no longer exists on disk.")
            if path in self.recent_files:
                self.recent_files.remove(path)
                self.save_recent()
                self.refresh_recent()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = App()
    w.show()
    sys.exit(app.exec_())
