import customtkinter as ctk
import threading
import re
import subprocess
from pathlib import Path
from orchestrator import Orchestrator

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# ─────────────────────────────────────────────────────────────────
# PALETĂ DE CULORI — security / industrial dark (GitHub-inspired)
# ─────────────────────────────────────────────────────────────────
C = {
    "bg":        "#0d1117",
    "card":      "#161b22",
    "card2":     "#1c2128",
    "border":    "#30363d",
    "accent":    "#1f6feb",
    "teal":      "#0891b2",
    "green":     "#238636",
    "red":       "#da3633",
    "orange":    "#d29922",
    "purple":    "#7c3aed",
    "pink":      "#db2777",
    "muted":     "#8b949e",
    "text":      "#e6edf3",
    "step_idle": "#21262d",
    "step_run":  "#1d4fad",
    "step_done": "#1a5c2a",
}

MONO = "Consolas"


class SupplyFuzzApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Supply-Fuzz  ·  Automated Vulnerability Discovery")
        self.geometry("1240x820")
        self.minsize(1000, 700)
        self.configure(fg_color=C["bg"])

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.is_scanning = False

        self._create_sidebar()
        self._create_main()
        self.load_history()

    # ─────────────────────────────────────────
    # SIDEBAR
    # ─────────────────────────────────────────
    def _create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=248, corner_radius=0,
                                    fg_color=C["bg"],
                                    border_width=1, border_color=C["border"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(3, weight=1)
        self.sidebar.grid_columnconfigure(0, weight=1)

        # ── Logo ──
        logo = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo.grid(row=0, column=0, padx=20, pady=(24, 0), sticky="ew")

        icon_lbl = ctk.CTkLabel(logo, text="⬡",
                                font=ctk.CTkFont(size=30),
                                text_color=C["accent"])
        icon_lbl.pack(side="left", padx=(0, 10))

        title_box = ctk.CTkFrame(logo, fg_color="transparent")
        title_box.pack(side="left")
        ctk.CTkLabel(title_box, text="Supply-Fuzz",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(title_box, text="Vulnerability Discovery",
                     font=ctk.CTkFont(size=10),
                     text_color=C["muted"]).pack(anchor="w")

        # ── Separator ──
        ctk.CTkFrame(self.sidebar, height=1, fg_color=C["border"]).grid(
            row=1, column=0, sticky="ew", padx=16, pady=20)

        # ── History label ──
        ctk.CTkLabel(self.sidebar, text="SCAN HISTORY",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=C["muted"]).grid(
            row=2, column=0, padx=20, sticky="w")

        # ── Scrollable history ──
        self.history_scroll = ctk.CTkScrollableFrame(
            self.sidebar, fg_color="transparent", scrollbar_button_color=C["border"])
        self.history_scroll.grid(row=3, column=0, sticky="nsew", padx=8, pady=(6, 4))
        self.history_scroll.grid_columnconfigure(0, weight=1)

        # ── Footer ──
        ctk.CTkFrame(self.sidebar, height=1, fg_color=C["border"]).grid(
            row=4, column=0, sticky="ew", padx=16)
        ctk.CTkLabel(self.sidebar, text="v1.0  ·  Supply Chain Security",
                     font=ctk.CTkFont(family=MONO, size=9),
                     text_color=C["muted"]).grid(
            row=5, column=0, padx=20, pady=12, sticky="w")

    # ─────────────────────────────────────────
    # HISTORY
    # ─────────────────────────────────────────
    def _find_reports(self):
        history_dir = Path("scans_history")
        if not history_dir.exists():
            return []
        reports = list(history_dir.glob("*/report.md")) + list(history_dir.glob("*.md"))
        return sorted(set(reports), key=lambda p: p.stat().st_mtime, reverse=True)

    def load_history(self):
        for w in self.history_scroll.winfo_children():
            w.destroy()

        reports = self._find_reports()
        if not reports:
            ctk.CTkLabel(self.history_scroll,
                         text="Nicio scanare în istoric",
                         text_color=C["muted"],
                         font=ctk.CTkFont(size=11)).grid(row=0, column=0, pady=24)
            return

        for i, fp in enumerate(reports):
            label = fp.parent.name if fp.name == "report.md" else fp.stem
            # "2026-06-05_11-57-36_cJSON" → pkg = "cJSON", ts = "2026-06-05 11:57"
            parts = label.rsplit("_", 1)
            pkg_name = parts[-1] if len(parts) > 1 else label
            timestamp = parts[0].replace("_", " ") if len(parts) > 1 else ""

            btn_frame = ctk.CTkFrame(self.history_scroll,
                                     fg_color=C["card2"], corner_radius=8,
                                     border_width=1, border_color=C["border"])
            btn_frame.grid(row=i, column=0, sticky="ew", pady=(0, 4))
            btn_frame.grid_columnconfigure(0, weight=1)
            btn_frame.bind("<Button-1>", lambda e, f=fp: self.display_past_report(f))

            top_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
            top_row.pack(fill="x", padx=12, pady=(9, 0))
            top_row.bind("<Button-1>", lambda e, f=fp: self.display_past_report(f))

            ctk.CTkLabel(top_row, text="📦",
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 6))
            ctk.CTkLabel(top_row, text=pkg_name[:20],
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=C["text"]).pack(side="left")

            ctk.CTkLabel(btn_frame,
                         text=timestamp[:16] if timestamp else label[:22],
                         font=ctk.CTkFont(family=MONO, size=9),
                         text_color=C["muted"]).pack(anchor="w", padx=12, pady=(0, 8))

    def display_past_report(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.render_report(content)
            self.tabview.set("Report")
        except Exception as e:
            self.render_report(f"Eroare la citire: {e}")

    # ─────────────────────────────────────────
    # MAIN AREA
    # ─────────────────────────────────────────
    def _create_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(
            main, fg_color=C["bg"],
            segmented_button_fg_color=C["card"],
            segmented_button_selected_color=C["accent"],
            segmented_button_selected_hover_color=C["teal"],
            segmented_button_unselected_color=C["card"],
            segmented_button_unselected_hover_color=C["card2"])
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)

        self.tabview.add("Dashboard")
        self.tabview.add("Report")

        self._build_dashboard()
        self._build_report_tab()

    # ─────────────────────────────────────────
    # TAB 1 — DASHBOARD
    # ─────────────────────────────────────────
    def _build_dashboard(self):
        tab = self.tabview.tab("Dashboard")
        tab.configure(fg_color="transparent")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        # ── Input card ──────────────────────
        input_card = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=10,
                                  border_width=1, border_color=C["border"])
        input_card.grid(row=0, column=0, sticky="ew", pady=(4, 10))
        input_card.grid_columnconfigure(0, weight=1)

        # URL row
        url_row = ctk.CTkFrame(input_card, fg_color="transparent")
        url_row.grid(row=0, column=0, padx=16, pady=(14, 6), sticky="ew")
        url_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(url_row, text="TARGET REPOSITORY",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=C["muted"]).grid(row=0, column=0, sticky="w")
        self.url_entry = ctk.CTkEntry(
            url_row,
            placeholder_text="https://github.com/user/repo  sau  cale locală",
            height=38, corner_radius=6,
            border_color=C["border"],
            font=ctk.CTkFont(family=MONO, size=13))
        self.url_entry.grid(row=1, column=0, sticky="ew")

        # Controls row
        ctrl = ctk.CTkFrame(input_card, fg_color="transparent")
        ctrl.grid(row=1, column=0, padx=16, pady=(4, 14), sticky="ew")
        ctrl.grid_columnconfigure(0, weight=1)

        left = ctk.CTkFrame(ctrl, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(left, text="Durată (min):",
                     text_color=C["muted"],
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=(0, 8))
        self.time_entry = ctk.CTkEntry(left, width=55, height=32, corner_radius=5,
                                       border_color=C["border"])
        self.time_entry.insert(0, "5")
        self.time_entry.grid(row=0, column=1, padx=(0, 20))

        self.use_dict_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(left, text="Dicționar hibrid (static→fuzz)",
                        variable=self.use_dict_var,
                        checkmark_color=C["teal"],
                        font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=(0, 8))

        self.scan_btn = ctk.CTkButton(
            ctrl, text="▶  START SCAN", height=36, corner_radius=6, width=150,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C["green"], hover_color="#1a7a2e",
            command=self.toggle_scan)
        self.scan_btn.grid(row=0, column=1, sticky="e")

        # ── Pipeline steps ───────────────────
        steps_card = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=10,
                                  border_width=1, border_color=C["border"])
        steps_card.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        steps_card.grid_columnconfigure((0, 1, 2, 3), weight=1)

        STEPS = [
            ("01", "Resolver",    "Dependencies"),
            ("02", "The Scout",   "Static Analysis"),
            ("03", "The Bridge",  "Harness + Seeds"),
            ("04", "The Hammer",  "Dynamic Fuzzing"),
        ]
        self.steps_ui = []
        for i, (num, name, sub) in enumerate(STEPS):
            is_last = (i == 3)
            step_frame = ctk.CTkFrame(steps_card, fg_color=C["step_idle"], corner_radius=8)
            step_frame.grid(row=0, column=i,
                            padx=(12 if i == 0 else 4, 12 if is_last else 4),
                            pady=12, sticky="ew")

            inner = ctk.CTkFrame(step_frame, fg_color="transparent")
            inner.pack(padx=14, pady=10, anchor="w")

            num_lbl = ctk.CTkLabel(inner, text=num,
                                   font=ctk.CTkFont(family=MONO, size=20, weight="bold"),
                                   text_color=C["muted"])
            num_lbl.pack(anchor="w")
            ctk.CTkLabel(inner, text=name,
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=C["text"]).pack(anchor="w")
            ctk.CTkLabel(inner, text=sub,
                         font=ctk.CTkFont(size=10),
                         text_color=C["muted"]).pack(anchor="w")

            self.steps_ui.append((step_frame, num_lbl))

        # ── Log console ──────────────────────
        console_wrap = ctk.CTkFrame(tab, fg_color="transparent")
        console_wrap.grid(row=2, column=0, sticky="nsew")
        console_wrap.grid_columnconfigure(0, weight=1)
        console_wrap.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(console_wrap, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ctk.CTkLabel(hdr, text="SCAN OUTPUT",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=C["muted"]).pack(side="left")
        ctk.CTkLabel(hdr, text="[ AFL++ / Docker ]",
                     font=ctk.CTkFont(family=MONO, size=9),
                     text_color=C["border"]).pack(side="right")

        self.results_textbox = ctk.CTkTextbox(
            console_wrap,
            font=ctk.CTkFont(family=MONO, size=12),
            fg_color=C["card"],
            text_color="#a9dc76",
            border_color=C["border"],
            border_width=1,
            corner_radius=8)
        self.results_textbox.grid(row=1, column=0, sticky="nsew")
        self.results_textbox.insert("0.0",
            "Sistema pregătit.\nIntroduceți URL-ul unui repo GitHub sau o cale locală și apăsați Start.\n")

    # ─────────────────────────────────────────
    # TAB 2 — REPORT
    # ─────────────────────────────────────────
    def _build_report_tab(self):
        tab = self.tabview.tab("Report")
        tab.configure(fg_color="transparent")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        self.report_scroll = ctk.CTkScrollableFrame(
            tab, fg_color="transparent",
            scrollbar_button_color=C["border"])
        self.report_scroll.grid(row=0, column=0, sticky="nsew")
        self.report_scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.report_scroll,
                     text="Rulați o scanare sau selectați un raport din istoric.",
                     text_color=C["muted"],
                     font=ctk.CTkFont(size=14)).grid(row=0, pady=60)

    # ─────────────────────────────────────────
    # STEP INDICATORS
    # ─────────────────────────────────────────
    def reset_steps_ui(self):
        for frame, num_lbl in self.steps_ui:
            frame.configure(fg_color=C["step_idle"])
            num_lbl.configure(text_color=C["muted"])

    def update_step_ui(self, idx, status="active"):
        if idx >= len(self.steps_ui):
            return
        frame, num_lbl = self.steps_ui[idx]
        if status == "active":
            frame.configure(fg_color=C["step_run"])
            num_lbl.configure(text_color="white")
        elif status == "done":
            frame.configure(fg_color=C["step_done"])
            num_lbl.configure(text_color="white")

    # ─────────────────────────────────────────
    # REPORT — PARSER
    # ─────────────────────────────────────────
    def _parse_report(self, md_text):
        """Parsează toate secțiunile Markdown → dict structurat."""
        data = {
            "date": "N/A", "package": "N/A",
            "exec_summary": {},
            "targets": [],
            "findings": [],
            "findings_grouped": {},
            "stats": {},
            "dict_active": False,
            "crashes": [],
        }

        section = None
        current_crash = None

        for line in md_text.split("\n"):
            ls = line.strip()

            # Detectare secțiuni
            if ls.startswith("## 1."):   section = "summary"
            elif ls.startswith("## 2b"): section = "findings"
            elif ls.startswith("## 2."):  section = "targets"
            elif ls.startswith("## 3."):  section = "stats"
            elif ls.startswith("## 4."):  section = "crashes"

            # Dată
            if "**Data generar" in ls:
                data["date"] = ls.split(":", 1)[-1].replace("*", "").strip()

            # Rezumat executiv
            if section == "summary" and "identificat" in ls.lower():
                m = re.search(r"\*\*(\d+)\*\* functii fuzzabile", ls)
                if m: data["exec_summary"]["entrypoints"] = m.group(1)
                m = re.search(r"\*\*(\d+)\*\* constatari", ls)
                if m: data["exec_summary"]["findings"] = m.group(1)
                m = re.search(r"\*\*(\d+)\*\* crash", ls)
                if m: data["exec_summary"]["crashes"] = m.group(1)

            # Targets
            if (section == "targets" and ls.startswith("|")
                    and "Severitate" not in ls and "---" not in ls):
                parts = [p.strip().replace("`", "") for p in ls.split("|") if p.strip()]
                if len(parts) >= 3:
                    data["targets"].append(parts)

            # Findings
            if (section == "findings" and ls.startswith("|")
                    and "Regula" not in ls and "---" not in ls):
                parts = [p.strip().replace("`", "") for p in ls.split("|") if p.strip()]
                if len(parts) >= 4:
                    data["findings"].append({"rule": parts[1], "loc": parts[2], "sev": parts[3]})

            # Stats
            if section == "stats":
                if "Statistici pentru" in ls:
                    data["package"] = ls.split("`")[1] if "`" in ls else "N/A"
                if "**Dictionar:**" in ls:
                    val = ls.split(":", 1)[-1].replace("*", "").strip()
                    data["stats"]["dict"] = val
                    data["dict_active"] = ("ACTIV" in val.upper() and
                                           "INACTIV" not in val.upper())
                KV = [
                    ("**Durata fuzzing:**", "duration"),
                    ("**Acoperire",         "coverage"),
                    ("**Elemente corpus",   "corpus"),
                    ("**Viteza:**",         "speed"),
                    ("**Total executii:**", "execs"),
                    ("**Stabilitate:**",    "stability"),
                    ("**Crashes:**",        "crashes"),
                ]
                for key, field in KV:
                    if key in ls:
                        data["stats"][field] = (ls.split(":", 1)[-1]
                                                .replace("*", "").strip())

            # Crashes
            if section == "crashes":
                if ls.startswith("### Crash #"):
                    if current_crash:
                        data["crashes"].append(current_crash)
                    ctype = ls.split("`")[1] if "`" in ls else "UNKNOWN"
                    num = ls.replace("### Crash #", "").split(":")[0].strip()
                    current_crash = {"num": num, "type": ctype}
                elif current_crash:
                    CRASH_KV = [
                        ("**Marime input:**",  "size"),
                        ("**Mărime input:**",  "size"),
                        ("**CVSS Estimat:**",  "cvss"),
                        ("**Preview ASCII:**", "ascii"),
                        ("**Fisier PoC:**",    "poc"),
                    ]
                    for key, field in CRASH_KV:
                        if key in ls:
                            val = (ls.split(":", 1)[-1]
                                   .replace("*", "").replace("`", "").strip())
                            if field == "cvss":
                                val = val.split(" ")[0]
                            current_crash[field] = val

        if current_crash:
            data["crashes"].append(current_crash)

        # Grupare findings după regulă
        counts = {}
        for f in data["findings"]:
            counts[f["rule"]] = counts.get(f["rule"], 0) + 1
        data["findings_grouped"] = counts

        return data

    # ─────────────────────────────────────────
    # REPORT — RENDERER
    # ─────────────────────────────────────────
    def render_report(self, md_text):
        for w in self.report_scroll.winfo_children():
            w.destroy()

        d = self._parse_report(md_text)
        row = [0]

        def add(widget, **kw):
            widget.grid(row=row[0], column=0, **kw)
            row[0] += 1

        def sep():
            ctk.CTkFrame(self.report_scroll, height=1, fg_color=C["border"]).grid(
                row=row[0], column=0, sticky="ew", pady=10)
            row[0] += 1

        def section_title(icon, text):
            f = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
            f.grid(row=row[0], column=0, sticky="w", pady=(4, 6))
            row[0] += 1
            ctk.CTkLabel(f, text=icon, font=ctk.CTkFont(size=16),
                         text_color=C["accent"]).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(f, text=text,
                         font=ctk.CTkFont(size=15, weight="bold"),
                         text_color=C["text"]).pack(side="left")

        # ── HEADER ─────────────────────────────────────
        header = ctk.CTkFrame(self.report_scroll, fg_color=C["card"],
                              corner_radius=10, border_width=1, border_color=C["border"])
        add(header, sticky="ew", pady=(0, 8))

        hdr_inner = ctk.CTkFrame(header, fg_color="transparent")
        hdr_inner.pack(padx=20, pady=16, anchor="w")

        ctk.CTkLabel(hdr_inner, text="⬡  Security Analysis Report",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(hdr_inner,
                     text=f"{d['date']}  ·  Target: {d['package']}",
                     font=ctk.CTkFont(family=MONO, size=11),
                     text_color=C["muted"]).pack(anchor="w", pady=(4, 0))

        # ── EXECUTIVE SUMMARY CARDS ─────────────────────
        es = d.get("exec_summary", {})
        raw_crashes = d["stats"].get("crashes", es.get("crashes", "0"))
        try:
            n_crashes = int(str(raw_crashes).replace("*", "").strip())
        except ValueError:
            n_crashes = 0

        sum_frame = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
        add(sum_frame, sticky="ew", pady=(0, 8))
        sum_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        summary_items = [
            ("🎯", "Entry-Points",     es.get("entrypoints", "—"),   C["accent"]),
            ("🔍", "Static Findings",  es.get("findings", "—"),      C["orange"]),
            ("💥", "Crashes",          str(n_crashes),
             C["red"] if n_crashes > 0 else C["green"]),
            ("⏱", "Duration",         d["stats"].get("duration", "—"), C["teal"]),
        ]
        for i, (icon, label, val, color) in enumerate(summary_items):
            card = ctk.CTkFrame(sum_frame, fg_color=C["card"], corner_radius=10,
                                border_width=1, border_color=C["border"])
            card.grid(row=0, column=i, padx=(0, 8) if i < 3 else 0, sticky="ew")

            accent_bar = ctk.CTkFrame(card, width=4, fg_color=color, corner_radius=2)
            accent_bar.pack(side="left", fill="y")

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(padx=16, pady=14, anchor="w")
            ctk.CTkLabel(inner, text=f"{icon}  {label}",
                         font=ctk.CTkFont(size=10),
                         text_color=C["muted"]).pack(anchor="w")
            ctk.CTkLabel(inner, text=str(val),
                         font=ctk.CTkFont(size=26, weight="bold"),
                         text_color=C["text"]).pack(anchor="w")

        sep()

        # ── ENTRY-POINTS TABLE ──────────────────────────
        section_title("🎯", "Identified Entry-Points (The Scout)")

        tbl = ctk.CTkFrame(self.report_scroll, fg_color=C["card"],
                           corner_radius=10, border_width=1, border_color=C["border"])
        add(tbl, sticky="ew", pady=(0, 8))
        tbl.grid_columnconfigure(2, weight=2)

        for ci, h in enumerate(["Package", "Function", "Source File", "Severity"]):
            ctk.CTkLabel(tbl, text=h,
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=C["muted"], anchor="w").grid(
                row=0, column=ci, padx=16, pady=(12, 6), sticky="w")

        ctk.CTkFrame(tbl, height=1, fg_color=C["border"]).grid(
            row=1, column=0, columnspan=4, sticky="ew", padx=12)

        if not d["targets"]:
            ctk.CTkLabel(tbl, text="No fuzzable entry-points found.",
                         text_color=C["muted"]).grid(row=2, columnspan=4, pady=12)
        else:
            for ri, target in enumerate(d["targets"], start=2):
                bg = C["card2"] if ri % 2 == 0 else "transparent"
                for ci, item in enumerate(target[:4]):
                    font = (ctk.CTkFont(family=MONO, size=12)
                            if ci in [1, 2] else ctk.CTkFont(size=12))
                    ctk.CTkLabel(tbl, text=item, fg_color=bg,
                                 font=font, text_color=C["text"], anchor="w").grid(
                        row=ri, column=ci, padx=16, pady=6, sticky="ew")

        sep()

        # ── STATIC FINDINGS ─────────────────────────────
        section_title("🔍", "Static Findings (CWE / Sinks)")

        FINDING_META = {
            "unsafe-string-copy":
                (C["red"],    "CWE-120", "Unsafe strcpy/strcat/sprintf/gets"),
            "unsafe-memcpy":
                (C["orange"], "CWE-122", "memcpy/memmove without bounds check"),
            "format-string-vulnerability":
                (C["red"],    "CWE-134", "Format string vulnerability"),
            "use-after-free-pattern":
                (C["red"],    "CWE-416", "Use-After-Free pattern"),
            "integer-overflow-in-alloc":
                (C["red"],    "CWE-190", "Integer overflow in allocation"),
            "unchecked-malloc":
                (C["orange"], "CWE-476", "malloc without NULL check"),
            "signed-unsigned-comparison":
                (C["orange"], "CWE-195", "Signed/unsigned comparison"),
        }

        findings_wrap = ctk.CTkFrame(self.report_scroll, fg_color=C["card"],
                                     corner_radius=10, border_width=1,
                                     border_color=C["border"])
        add(findings_wrap, sticky="ew", pady=(0, 8))
        findings_wrap.grid_columnconfigure(1, weight=1)

        if not d["findings_grouped"]:
            ctk.CTkLabel(findings_wrap, text="No static findings.",
                         text_color=C["muted"], pady=12).grid(row=0)
        else:
            for ri, (rule, count) in enumerate(d["findings_grouped"].items()):
                color, cwe, desc = FINDING_META.get(rule, (C["muted"], "", rule))
                bg = C["card2"] if ri % 2 == 0 else "transparent"

                row_f = ctk.CTkFrame(findings_wrap, fg_color=bg, corner_radius=0)
                row_f.grid(row=ri, column=0, columnspan=3, sticky="ew")
                row_f.grid_columnconfigure(1, weight=1)

                ctk.CTkFrame(row_f, width=3, height=34,
                              fg_color=color, corner_radius=2).grid(
                    row=0, column=0, padx=(10, 12), pady=8)

                info = ctk.CTkFrame(row_f, fg_color="transparent")
                info.grid(row=0, column=1, sticky="w")

                ctk.CTkLabel(info, text=rule,
                             font=ctk.CTkFont(family=MONO, size=12),
                             text_color=C["text"]).pack(side="left", padx=(0, 10))
                if cwe:
                    ctk.CTkLabel(info, text=cwe,
                                 font=ctk.CTkFont(size=10, weight="bold"),
                                 text_color=color).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(info, text=desc,
                             font=ctk.CTkFont(size=11),
                             text_color=C["muted"]).pack(side="left")

                ctk.CTkLabel(row_f,
                             text=f" {count} ",
                             font=ctk.CTkFont(family=MONO, size=11, weight="bold"),
                             fg_color=color, corner_radius=4,
                             text_color="white").grid(row=0, column=2, padx=16)

        sep()

        # ── FUZZER STATS ────────────────────────────────
        section_title("🔨", "Dynamic Validation (The Hammer)")

        if d["stats"]:
            dict_color = C["purple"] if d["dict_active"] else C["step_idle"]
            dict_text = ("🧬  Hybrid Dictionary  ACTIVE  (static → fuzz)"
                         if d["dict_active"]
                         else "○  Dictionary  INACTIVE  (baseline run)")
            badge = ctk.CTkFrame(self.report_scroll, fg_color=dict_color, corner_radius=8)
            add(badge, sticky="w", pady=(0, 10))
            ctk.CTkLabel(badge, text=dict_text,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="white", padx=18, pady=8).pack()

            stats_grid = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
            add(stats_grid, sticky="ew", pady=(0, 8))
            stats_grid.grid_columnconfigure((0, 1, 2, 3), weight=1)

            n_c = d["stats"].get("crashes", "0")
            STAT_CARDS = [
                ("Coverage",      d["stats"].get("coverage", "—"),  C["teal"]),
                ("Corpus",        d["stats"].get("corpus", "—"),    C["purple"]),
                ("Exec / sec",    d["stats"].get("speed", "—"),     C["accent"]),
                ("Total Execs",   d["stats"].get("execs", "—"),     C["orange"]),
                ("Stability",     d["stats"].get("stability", "—"), C["green"]),
                ("Duration",      d["stats"].get("duration", "—"),  C["pink"]),
                ("Crashes Found", n_c,
                 C["red"] if n_c not in ("0", "—", "") else C["green"]),
            ]
            for i, (label, val, color) in enumerate(STAT_CARDS):
                r, c = divmod(i, 4)
                card = ctk.CTkFrame(stats_grid, fg_color=C["card"], corner_radius=8,
                                    border_width=1, border_color=C["border"])
                card.grid(row=r, column=c, padx=(0, 8), pady=(0, 8), sticky="ew")

                ctk.CTkFrame(card, height=3, fg_color=color, corner_radius=2).pack(fill="x")
                inner = ctk.CTkFrame(card, fg_color="transparent")
                inner.pack(padx=14, pady=10, anchor="w")
                ctk.CTkLabel(inner, text=str(val),
                             font=ctk.CTkFont(family=MONO, size=20, weight="bold"),
                             text_color=C["text"]).pack(anchor="w")
                ctk.CTkLabel(inner, text=label,
                             font=ctk.CTkFont(size=10),
                             text_color=C["muted"]).pack(anchor="w")
        else:
            self._report_alert(
                C["orange"], "⚠️",
                "Fuzzing statistics unavailable.",
                "The fuzzer may not have run (compilation failure or manual stop).")
            row[0] += 1

        sep()

        # ── CRASHES ─────────────────────────────────────
        section_title("💥", f"Confirmed Crashes & PoC  ({len(d['crashes'])})")

        if not d["crashes"]:
            no_crash = ctk.CTkFrame(self.report_scroll, fg_color=C["step_done"],
                                    corner_radius=8)
            add(no_crash, sticky="ew", pady=(0, 8))
            ctk.CTkLabel(no_crash, text="✅  No crashes found in this session.",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         text_color="white", pady=16).pack()
        elif "V8" in md_text or "napi_" in md_text.lower():
            self._report_alert(C["purple"], "🧠",
                               "ARCHITECTURAL LIMITATION DETECTED",
                               "Module uses native Node.js (V8/N-API) bindings. "
                               "Classic C/C++ fuzzing was skipped. "
                               "In-Process instrumentation would be required.")
            row[0] += 1
        else:
            crashes_container = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
            add(crashes_container, sticky="ew", pady=(0, 8))
            crashes_container.grid_columnconfigure(0, weight=1)

            for ci, crash in enumerate(d["crashes"]):
                self._render_crash_card(crash, crashes_container, ci)

    def _report_alert(self, color, icon, title, body):
        frame = ctk.CTkFrame(self.report_scroll, fg_color=color, corner_radius=8)
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(padx=18, pady=14, anchor="w")
        ctk.CTkLabel(inner, text=f"{icon}  {title}",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="white").pack(anchor="w")
        if body:
            ctk.CTkLabel(inner, text=body,
                         font=ctk.CTkFont(size=11),
                         text_color="white", wraplength=700,
                         justify="left").pack(anchor="w", pady=(4, 0))

    def _render_crash_card(self, crash, container, r):
        ctype = crash.get("type", "UNKNOWN")
        cvss_str = crash.get("cvss", "—")
        try:
            cvss_f = float(cvss_str)
            cvss_color = (C["red"] if cvss_f >= 7.0
                          else C["orange"] if cvss_f >= 4.0
                          else C["green"])
        except ValueError:
            cvss_f = 0.0
            cvss_color = C["muted"]

        card = ctk.CTkFrame(container, fg_color=C["card"], corner_radius=8,
                            border_width=1, border_color=C["border"])
        card.grid(row=r, column=0, sticky="ew", pady=(0, 6))
        card.grid_columnconfigure(0, weight=1)

        # Card header bar
        hdr = ctk.CTkFrame(card, fg_color=C["card2"], corner_radius=6)
        hdr.pack(fill="x", padx=4, pady=(4, 0))

        left_hdr = ctk.CTkFrame(hdr, fg_color="transparent")
        left_hdr.pack(side="left", padx=14, pady=10)

        ctk.CTkLabel(left_hdr,
                     text=f"CRASH  #{crash.get('num', '?')}",
                     font=ctk.CTkFont(family=MONO, size=10),
                     text_color=C["muted"]).pack(anchor="w")
        ctk.CTkLabel(left_hdr, text=ctype,
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=C["text"]).pack(anchor="w")

        ctk.CTkLabel(hdr,
                     text=f"  CVSS  {cvss_str}  ",
                     font=ctk.CTkFont(family=MONO, size=13, weight="bold"),
                     fg_color=cvss_color, corner_radius=6,
                     text_color="white").pack(side="right", padx=14, pady=12)

        # Details row
        det = ctk.CTkFrame(card, fg_color="transparent")
        det.pack(fill="x", padx=16, pady=(8, 12))
        det.grid_columnconfigure(0, weight=1)
        det.grid_columnconfigure(1, weight=2)

        size_v = crash.get("size", "—")
        ctk.CTkLabel(det,
                     text=f"Size    {size_v}",
                     font=ctk.CTkFont(family=MONO, size=12),
                     text_color=C["muted"]).grid(row=0, column=0, sticky="w")

        ascii_v = crash.get("ascii", "")
        if ascii_v:
            preview = ascii_v[:60] + ("…" if len(ascii_v) > 60 else "")
            ctk.CTkLabel(det,
                         text=f"ASCII   {preview}",
                         font=ctk.CTkFont(family=MONO, size=11),
                         text_color=C["teal"]).grid(row=0, column=1, sticky="w")

    # ─────────────────────────────────────────
    # SCAN CONTROL
    # ─────────────────────────────────────────
    def toggle_scan(self):
        if not self.is_scanning:
            url = self.url_entry.get().strip()
            if not url:
                self.results_textbox.insert("end", "[!] Eroare: Introdu URL valid.\n")
                return
            try:
                minutes = float(self.time_entry.get())
            except ValueError:
                self.results_textbox.insert("end", "[!] Eroare: Timp invalid.\n")
                return

            self.is_scanning = True
            self.scan_btn.configure(text="⏹  STOP",
                                    fg_color=C["red"], hover_color="#b02a2a")
            self.reset_steps_ui()
            self.results_textbox.delete("0.0", "end")

            use_dict = self.use_dict_var.get()
            mode = "hibrid" if use_dict else "baseline"
            self.results_textbox.insert("end",
                f"[→] Target  : {url}\n"
                f"[→] Mod     : {mode}\n"
                f"[→] Durată  : {minutes} min\n"
                f"{'─' * 62}\n")
            self.tabview.set("Dashboard")

            threading.Thread(target=self.run_real_scan,
                             args=(url, minutes, use_dict), daemon=True).start()
        else:
            self.results_textbox.insert("end", "\n[!] Oprire de urgență...\n")
            self.is_scanning = False
            self.scan_btn.configure(text="▶  START SCAN",
                                    fg_color=C["green"], hover_color="#1a7a2e",
                                    state="disabled")
            threading.Thread(
                target=lambda: subprocess.run(
                    ["docker", "stop", "supply_fuzz_run"], capture_output=True),
                daemon=True).start()

    def run_real_scan(self, url, minutes, use_dict=True):
        timeout_seconds = int(minutes * 60)

        def update_gui(message, progress=None):
            self.results_textbox.insert("end", message + "\n")
            self.results_textbox.see("end")

            if progress is not None:
                starts = [0.15, 0.40, 0.60, 0.80]
                for i, th in enumerate(starts):
                    if progress >= th:
                        self.update_step_ui(i, "active")
                    if i + 1 < len(starts) and progress >= starts[i + 1]:
                        self.update_step_ui(i, "done")
                if progress >= 1.0:
                    self.update_step_ui(3, "done")

        try:
            orch = Orchestrator(target_input=url, timeout=timeout_seconds,
                                status_callback=update_gui,
                                use_dictionary=use_dict)
            orch.run()

            reports = self._find_reports()
            if reports:
                with open(reports[0], "r", encoding="utf-8") as f:
                    content = f.read()
                self.after(0, lambda c=content: self.render_report(c))
                self.after(300, lambda: self.tabview.set("Report"))

        except Exception as e:
            update_gui(f"[!] Eroare critică: {str(e)}", 0)
        finally:
            self.is_scanning = False
            self.after(0, lambda: self.scan_btn.configure(
                text="▶  START SCAN",
                fg_color=C["green"], hover_color="#1a7a2e",
                state="normal"))
            self.after(0, self.load_history)


if __name__ == "__main__":
    app = SupplyFuzzApp()
    app.mainloop()