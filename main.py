import sys, os, time, math, json, hashlib, re, base64, binascii, webbrowser
from dataclasses import dataclass
from datetime import datetime

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QProgressBar, QTextEdit, QCheckBox, QMessageBox, QFrame,
    QSplitter, QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
)

# -----------------------------
# Data containers
# -----------------------------
@dataclass
class Finding:
    title: str
    severity: str
    weight: int
    explanation: str
    evidence: str


# -----------------------------
# Worker (NOT UI)
# -----------------------------
class ScannerWorker(QObject):
    progress = pyqtSignal(int, str)        # percent, status text
    finished = pyqtSignal(dict)            # final report dict

    def __init__(self, path: str, advanced: bool = False):
        super().__init__()
        self.path = path
        self.advanced = advanced

        # intentionally opinionated thresholds (non-round)
        self.entropy_high = 7.23
        self.large_file_warn = 48 * 1024 * 1024  # 48MB feels "uncomfortable"
        self.full_read_limit = 20 * 1024 * 1024  # read full content <= 20MB
        self.sample_read = 2 * 1024 * 1024       # otherwise sample 2MB

        # manual priority map (Phase 14)
        self.sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

        # detection patterns (written from memory-ish, not copied)
        # You can tune weights after observing outputs (Phase 12).
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
                (b"VirtualAlloc", "High", 18, "Memory allocation APIs sometimes appear in injectors/packers."),
                (b"WriteProcessMemory", "High", 22, "Process memory writing can be used by malware."),
            ],
            "zip": [
                (b"vbaProject.bin", "High", 22, "Office macro container name appears (possible macros)."),
                (b"word/_rels", "Low", 6, "Office doc structure detected (not bad by itself)."),
            ],
            "pdf": [
                (b"/JS", "Medium", 14, "PDF contains JavaScript markers (can be abused)."),
                (b"/OpenAction", "Medium", 12, "PDF auto-action markers appear."),
            ],
            "unknown": [
                (b"powershell", "Medium", 14, "Contains PowerShell-related text."),
                (b"http://", "Medium", 10, "Contains URL text."),
                (b"https://", "Medium", 10, "Contains URL text."),
            ],
        }

        # generic suspicious strings (background noise detectors)
        self.generic_tokens = [
            b"powershell", b"-enc", b"cmd.exe", b"rundll32", b"reg add", b"schtasks",
            b"http://", b"https://", b"wget", b"curl", b"pastebin", b"discordapp",
            b"token", b"stealer", b"keylogger"
        ]

        # “Human threshold” scoring bands
        self.band_low = 39
        self.band_med = 69

    def run(self):
        try:
            report = self.scan_file(self.path)
            self.finished.emit(report)
        except Exception as e:
            self.finished.emit({"error": f"{type(e).__name__}: {str(e)}", "path": self.path})

    # -----------------------------
    # Core scan pipeline
    # -----------------------------
    def scan_file(self, path: str) -> dict:
        t0 = time.time()

        self.progress.emit(2, "Touching the file (bytes first)")
        size = os.path.getsize(path)
        filename = os.path.basename(path)

        warnings = []
        if size >= self.large_file_warn:
            warnings.append(f"File is large ({size} bytes). Scan uses sampling to avoid heavy memory use.")

        # read initial bytes for magic
        self.progress.emit(7, "Reading header (magic bytes)")
        with open(path, "rb") as f:
            head = f.read(4096)

        # classify type (magic + extension)
        self.progress.emit(12, "Classifying file type (magic beats extension)")
        kind, kind_reason = self.classify(path, head)

        # hashing incrementally (no full load just for hashing)
        self.progress.emit(20, "Hashing (incremental stream)")
        sha256, md5 = self.stream_hashes(path)

        # content read size-aware
        self.progress.emit(33, "Reading content (size-aware)")
        data = self.read_content_size_aware(path, size)

        # compute entropy on whatever we read (sample or full)
        self.progress.emit(45, "Entropy measurement")
        ent = self.entropy(data)

        # extract printable strings (simple)
        self.progress.emit(55, "Extracting printable strings")
        big_text = self.extract_printable_strings(data)

        # detections + scoring
        self.progress.emit(66, "Applying detections + scoring")
        findings = []
        score = 0

        # baseline: executable files are inherently riskier
        if kind == "exe":
            f = Finding(
                title="Windows executable",
                severity="Low",
                weight=10,
                explanation="Executables can run code. Treat unknown executables as higher risk than documents.",
                evidence="MZ header / .exe style"
            )
            findings.append(f)
            score += f.weight

        # entropy check
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

        # generic token hits
        lower_text = big_text.lower()
        hits = [tok for tok in self.generic_tokens if tok in lower_text]
        if len(hits) >= 2:
            w = min(35, 10 + 5 * len(hits))  # cap influence
            findings.append(Finding(
                title="Suspicious command/network strings",
                severity="High",
                weight=w,
                explanation="Multiple strings commonly used in malware, downloaders, or credential theft appear.",
                evidence=f"hits={len(hits)} (capped weight)"
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

        # type-specific rules
        for pat, sev, w, expl in self.type_rules.get(kind, []) + self.type_rules.get("unknown", []):
            if pat in lower_text:
                findings.append(Finding(
                    title=f"Pattern: {pat.decode(errors='ignore')}",
                    severity=sev,
                    weight=w,
                    explanation=expl,
                    evidence=f"match in extracted strings"
                ))
                score += w

        # advanced behavior
        decoded_snips = []
        pe_meta = {}
        if self.advanced:
            self.progress.emit(76, "Advanced: deobfuscation attempts (limited)")
            decoded_snips = self.try_decode_base64ish(big_text)

            if decoded_snips:
                # rescan decoded snippets with reduced weight, no recursion
                for i, s in enumerate(decoded_snips[:4]):
                    sl = s.lower()
                    dhits = [tok for tok in self.generic_tokens if tok in sl]
                    if len(dhits) >= 2:
                        w = 10  # reduced weight
                        findings.append(Finding(
                            title="Decoded snippet contains suspicious strings",
                            severity="Medium",
                            weight=w,
                            explanation="A decoded-looking substring contains multiple suspicious tokens.",
                            evidence=f"decoded_hits={len(dhits)} snippet#{i}"
                        ))
                        score += w

            if kind == "exe":
                self.progress.emit(83, "Advanced: light PE metadata checks")
                pe_meta, pe_findings = self.light_pe_checks(path)
                for f in pe_findings:
                    findings.append(f)
                    score += f.weight

        # cap influence arbitrarily (Phase 3)
        score = max(0, min(100, score))

        # decide risk levels after scoring (Phase 5)
        if score >= self.band_med:
            risk = "High"
        elif score >= self.band_low:
            risk = "Medium"
        else:
            risk = "Low"

        # sort findings by perceived severity, then weight
        findings.sort(key=lambda x: (self.sev_rank.get(x.severity, 9), -x.weight))

        # recommendations + hooks
        self.progress.emit(92, "Preparing human-readable summary")
        recs = self.recommend(risk)
        hooks = {
            "virustotal_sha256": f"https://www.virustotal.com/gui/search/{sha256}",
            "google_sha256": f"https://www.google.com/search?q={sha256}",
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

    # -----------------------------
    # Helpers (some are intentionally a bit blunt)
    # -----------------------------
    def classify(self, path: str, head: bytes):
        ext = os.path.splitext(path)[1].lower()

        if head.startswith(b"MZ"):
            return "exe", "magic=MZ"
        if head.startswith(b"\x7FELF"):
            return "elf", "magic=ELF"
        if head.startswith(b"%PDF"):
            return "pdf", "magic=%PDF"
        if head.startswith(b"\x50\x4B\x03\x04"):
            # could be zip, docx, jar, etc.
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
        else:
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
        # Look for long-ish base64-ish chunks; decode only a few; ignore failures
        # This is intentionally imperfect (Phase 6).
        decoded = []
        # bytes regex for base64-like: A-Z a-z 0-9 + / = and length >= 80
        for m in re.finditer(rb"[A-Za-z0-9+/=]{80,}", big_text):
            chunk = m.group(0)
            # reduce false positives: needs '=' or length multiple-ish
            if b"=" not in chunk and (len(chunk) % 4 != 0):
                continue
            # only try a few
            if len(decoded) >= 6:
                break
            try:
                raw = base64.b64decode(chunk[:3000], validate=False)
                # keep only printable-ish decoded
                if raw and sum(1 for b in raw[:200] if 32 <= b <= 126) >= 40:
                    decoded.append(raw)
            except Exception:
                continue
        return decoded

    def light_pe_checks(self, path: str):
        """
        Super-light PE checks:
        - validate MZ + PE signature via offsets
        - read timestamp
        - read section names
        No deep validation. Anomalies -> suspicious.
        """
        meta = {}
        findings = []
        try:
            with open(path, "rb") as f:
                mz = f.read(64)
                if not mz.startswith(b"MZ"):
                    return meta, findings
                # e_lfanew at 0x3C
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

                file_header = f.read(20)  # IMAGE_FILE_HEADER
                if len(file_header) < 20:
                    return meta, findings

                # timestamp offset in file header is at +4 from start of file header
                ts = int.from_bytes(file_header[4:8], "little", signed=False)
                meta["timestamp_raw"] = ts
                if ts != 0:
                    try:
                        dt = datetime.utcfromtimestamp(ts)
                        meta["timestamp_utc"] = dt.isoformat(timespec="seconds") + "Z"
                        # weird heuristics: very old/new timestamps can be suspicious
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

                # number of sections at offset 2 of file header
                num_sections = int.from_bytes(file_header[2:4], "little", signed=False)
                meta["num_sections"] = num_sections

                # skip optional header: size is at file_header[16:18]
                opt_size = int.from_bytes(file_header[16:18], "little", signed=False)
                f.seek(opt_size, 1)

                # section table entries: 40 bytes each
                section_names = []
                for _ in range(min(num_sections, 12)):  # cap
                    sec = f.read(40)
                    if len(sec) < 40:
                        break
                    name = sec[0:8].split(b"\x00", 1)[0].decode(errors="ignore")
                    if name:
                        section_names.append(name)

                meta["section_names"] = section_names

                # heuristic anomalies: many strange short sections or weird names
                weird = [n for n in section_names if n.lower() in ("upx0", "upx1", "aspack", ".packed", "petite")]
                if weird:
                    findings.append(Finding(
                        title="Possible packer sections",
                        severity="High",
                        weight=20,
                        explanation="Section names suggest the executable may be packed/compressed.",
                        evidence=f"sections={weird}"
                    ))

                if num_sections >= 8 and "High" not in [f.severity for f in findings]:
                    findings.append(Finding(
                        title="Many PE sections",
                        severity="Low",
                        weight=6,
                        explanation="Many sections can be normal, but it’s sometimes seen in packed builds.",
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
                "If you must investigate, search the SHA256 hash on external services (manual).",
                "If it came from a chat/download link, assume it is unsafe until proven otherwise."
            ]
        if risk == "Medium":
            return [
                "Be cautious: only open if you trust the source.",
                "Prefer opening documents in a safe viewer or sandboxed environment.",
                "You can verify the SHA256 hash externally (manual)."
            ]
        return [
            "No strong suspicious signals detected in this scan.",
            "Still use common sense: only open files from trusted sources.",
            "If something feels off, verify using a trusted AV or external hash search."
        ]


# -----------------------------
# UI
# -----------------------------
class DropFrame(QFrame):
    dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)

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
        self.setWindowTitle("Intelligent Malware Detector (Heuristic)")
        self.resize(980, 620)

        self.file_path = None
        self.last_report = None

        # --- Top controls ---
        self.choose_btn = QPushButton("Choose file…")
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setEnabled(False)

        self.advanced_cb = QCheckBox("Advanced mode")
        self.export_btn = QPushButton("Export JSON…")
        self.export_btn.setEnabled(False)

        self.vt_btn = QPushButton("Open VirusTotal (SHA256)")
        self.google_btn = QPushButton("Google hash")
        self.vt_btn.setEnabled(False)
        self.google_btn.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(self.choose_btn)
        top.addWidget(self.scan_btn)
        top.addSpacing(12)
        top.addWidget(self.advanced_cb)
        top.addStretch(1)
        top.addWidget(self.export_btn)
        top.addWidget(self.vt_btn)
        top.addWidget(self.google_btn)

        # --- Drop area + status ---
        self.drop = DropFrame()
        drop_layout = QVBoxLayout()
        self.path_label = QLabel("Drop a file here or click “Choose file…”")
        self.path_label.setWordWrap(True)
        drop_layout.addWidget(self.path_label)
        self.drop.setLayout(drop_layout)

        self.progress = QProgressBar()
        self.status = QLabel("Idle.")

        # --- Dashboard summary (left) ---
        self.risk_big = QLabel("—")
        self.risk_big.setFont(QFont("Segoe UI", 26, QFont.Bold))
        self.score_big = QLabel("Score: —")
        self.score_big.setFont(QFont("Segoe UI", 16, QFont.Bold))

        self.meta_small = QLabel("")
        self.meta_small.setWordWrap(True)

        dash = QVBoxLayout()
        dash.addWidget(self.risk_big)
        dash.addWidget(self.score_big)
        dash.addSpacing(6)
        dash.addWidget(self.meta_small)
        dash.addStretch(1)

        dash_box = QFrame()
        dash_box.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        dash_box.setLayout(dash)

        # --- Findings table (right top) ---
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Weight", "Title", "Explanation"])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

        # --- Details log (right bottom) ---
        self.details = QTextEdit()
        self.details.setReadOnly(True)

        right = QSplitter(Qt.Vertical)
        right.addWidget(self.table)
        right.addWidget(self.details)
        right.setSizes([320, 280])

        mid = QSplitter(Qt.Horizontal)
        mid.addWidget(dash_box)
        mid.addWidget(right)
        mid.setSizes([300, 680])

        # main layout
        layout = QVBoxLayout()
        layout.addLayout(top)
        layout.addWidget(self.drop)
        layout.addWidget(self.progress)
        layout.addWidget(self.status)
        layout.addWidget(mid)
        self.setLayout(layout)

        # signals
        self.choose_btn.clicked.connect(self.pick_file)
        self.scan_btn.clicked.connect(self.start_scan)
        self.export_btn.clicked.connect(self.export_json)
        self.vt_btn.clicked.connect(self.open_vt)
        self.google_btn.clicked.connect(self.open_google)
        self.drop.dropped.connect(self.set_file)

        # worker thread handles
        self.thread = None
        self.worker = None

        self.apply_risk_style("—")

    def set_file(self, path: str):
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Not a file", "Please drop a valid file.")
            return
        self.file_path = path
        self.path_label.setText(path)
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
        self.export_btn.setEnabled(False)
        self.vt_btn.setEnabled(False)
        self.google_btn.setEnabled(False)
        self.risk_big.setText("—")
        self.score_big.setText("Score: —")
        self.meta_small.setText("")
        self.apply_risk_style("—")
        self.table.setRowCount(0)
        self.details.clear()

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
            self.apply_risk_style("High")
            self.risk_big.setText("ERROR")
            self.score_big.setText("Score: —")
            self.details.setText(json.dumps(report, indent=2))
            self.status.setText("Scan finished with an error (partial report).")
            return

        risk = report.get("risk_level", "—")
        score = report.get("risk_score", "—")
        self.apply_risk_style(risk)
        self.risk_big.setText(risk.upper())
        self.score_big.setText(f"Score: {score}")

        meta = (
            f"File: {report.get('filename')}\n"
            f"Type: {report.get('type_guess')} ({report.get('type_reason')})\n"
            f"Size: {report.get('size_bytes')} bytes\n"
            f"SHA256: {report.get('sha256')}\n"
            f"Entropy(sample): {report.get('entropy_sample')}\n"
            f"Advanced: {report.get('advanced', {}).get('enabled')}\n"
        )
        self.meta_small.setText(meta)

        # table findings
        findings = report.get("findings", [])
        self.table.setRowCount(len(findings))
        for r, f in enumerate(findings):
            self.table.setItem(r, 0, QTableWidgetItem(str(f.get("severity", ""))))
            self.table.setItem(r, 1, QTableWidgetItem(str(f.get("weight", ""))))
            self.table.setItem(r, 2, QTableWidgetItem(str(f.get("title", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(f.get("explanation", ""))))

        # details: render what user sees (Phase 17) but still include JSON for trust
        view = {
            "risk_level": report.get("risk_level"),
            "risk_score": report.get("risk_score"),
            "warnings": report.get("warnings"),
            "recommendations": report.get("recommendations"),
            "external_validation": report.get("external_validation"),
            "advanced": report.get("advanced"),
            "note": report.get("note"),
        }
        self.details.setText(json.dumps(view, indent=2))

        # enable external hooks
        self.vt_btn.setEnabled(True)
        self.google_btn.setEnabled(True)

        self.status.setText("Done.")

    def apply_risk_style(self, risk: str):
        # Visual dominance over logic (Phase 26): color first.
        if risk == "High":
            self.risk_big.setStyleSheet("color: #d32f2f;")  # red
        elif risk == "Medium":
            self.risk_big.setStyleSheet("color: #f9a825;")  # yellow
        elif risk == "Low":
            self.risk_big.setStyleSheet("color: #2e7d32;")  # green
        else:
            self.risk_big.setStyleSheet("color: #444;")

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
            QMessageBox.information(self, "Exported", f"Saved:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export failed", str(e))

    def open_vt(self):
        if not self.last_report:
            return
        url = self.last_report.get("external_validation", {}).get("virustotal_sha256")
        if url:
            webbrowser.open(url)

    def open_google(self):
        if not self.last_report:
            return
        url = self.last_report.get("external_validation", {}).get("google_sha256")
        if url:
            webbrowser.open(url)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = App()
    w.show()
    sys.exit(app.exec_())
