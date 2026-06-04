import customtkinter as ctk
import threading
from pathlib import Path
from orchestrator import Orchestrator

# Setări generale de aspect
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SupplyFuzzApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Supply-Fuzz Dashboard")
        self.geometry("1100x750")

        # Layout principal: 2 coloane
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.is_scanning = False

        self.create_sidebar()
        self.create_main_area()
        self.load_history()

    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(20, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="🛡️ Supply-Fuzz", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.history_label = ctk.CTkLabel(self.sidebar_frame, text="Istoric Scanări:", anchor="w", font=ctk.CTkFont(weight="bold"))
        self.history_label.grid(row=1, column=0, padx=20, pady=(10, 10), sticky="w")

    def _find_reports(self):
        """Returneaza toate rapoartele, cele mai noi primele.
        Rapoartele sunt in scans_history/<timestamp>_<pachet>/report.md.
        Includem si eventuale rapoarte vechi salvate direct ca *.md."""
        history_dir = Path("scans_history")
        if not history_dir.exists():
            return []
        reports = list(history_dir.glob("*/report.md")) + list(history_dir.glob("*.md"))
        # sortam dupa data modificarii, cele mai noi primele
        reports = sorted(set(reports), key=lambda p: p.stat().st_mtime, reverse=True)
        return reports

    def load_history(self):
        for widget in self.sidebar_frame.winfo_children():
            if isinstance(widget, ctk.CTkButton):
                widget.destroy()

        row_idx = 2
        for file_path in self._find_reports():
            # Eticheta = numele folderului (timestamp_pachet), nu "report"
            btn_text = file_path.parent.name if file_path.name == "report.md" else file_path.stem
            if len(btn_text) > 22: btn_text = btn_text[:19] + "..."

            btn = ctk.CTkButton(
                self.sidebar_frame, text=btn_text, fg_color="transparent",
                border_width=1, text_color=("gray10", "#DCE4EE"),
                command=lambda f=file_path: self.display_past_report(f)
            )
            btn.grid(row=row_idx, column=0, padx=20, pady=5, sticky="ew")
            row_idx += 1

    def display_past_report(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.render_beautiful_report(content)
            self.tabview.set("Raport Final")
        except Exception as e:
            self.render_beautiful_report(f"Eroare la citire: {e}")

    def create_main_area(self):
        self.tabview = ctk.CTkTabview(self, width=800)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.tabview.add("Dashboard")
        self.tabview.add("Raport Final")

        # --- TAB 1: DASHBOARD ---
        tab_dash = self.tabview.tab("Dashboard")
        tab_dash.grid_columnconfigure(0, weight=1)
        tab_dash.grid_rowconfigure(2, weight=1)

        self.input_frame = ctk.CTkFrame(tab_dash)
        self.input_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Introduceți URL-ul GitHub...")
        self.url_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.time_label = ctk.CTkLabel(self.input_frame, text="Minute:")
        self.time_label.grid(row=0, column=1, padx=(10, 0))
        
        self.time_entry = ctk.CTkEntry(self.input_frame, width=50)
        self.time_entry.insert(0, "1")
        self.time_entry.grid(row=0, column=2, padx=(5, 10))

        self.scan_btn = ctk.CTkButton(self.input_frame, text="▶ Start Scanare", command=self.toggle_scan, fg_color="#28a745", hover_color="#218838")
        self.scan_btn.grid(row=0, column=3, padx=10, pady=10)

        self.progress_frame = ctk.CTkFrame(tab_dash, fg_color="transparent")
        self.progress_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.progress_frame.grid_columnconfigure((0,1,2,3), weight=1)

        self.steps_ui = []
        for i, name in enumerate(["1. Resolver", "2. The Scout", "3. The Bridge", "4. The Hammer"]):
            lbl = ctk.CTkLabel(self.progress_frame, text=f"⏳ {name}", fg_color="gray30", corner_radius=5, padx=10, pady=5)
            lbl.grid(row=0, column=i, padx=5, sticky="ew")
            self.steps_ui.append(lbl)

        self.results_textbox = ctk.CTkTextbox(tab_dash, font=ctk.CTkFont(family="Consolas", size=12))
        self.results_textbox.grid(row=2, column=0, sticky="nsew")
        self.results_textbox.insert("0.0", "Aștept comenzi...\n")

        # --- TAB 2: RAPORT FINAL (Gata cu Textbox-ul, folosim ScrollableFrame) ---
        tab_report = self.tabview.tab("Raport Final")
        tab_report.grid_columnconfigure(0, weight=1)
        tab_report.grid_rowconfigure(0, weight=1)

        self.report_scroll = ctk.CTkScrollableFrame(tab_report, fg_color="transparent")
        self.report_scroll.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.report_scroll.grid_columnconfigure(0, weight=1)

        # Mesaj default
        self.default_lbl = ctk.CTkLabel(self.report_scroll, text="Aici va apărea raportul detaliat...", text_color="gray50")
        self.default_lbl.grid(row=0, column=0, pady=50)

    def render_beautiful_report(self, md_text):
        """Parsează fișierul Markdown și creează o interfață grafică uimitoare."""
        # Curățăm tot ce era înainte pe ecran
        for widget in self.report_scroll.winfo_children():
            widget.destroy()

        # 1. Parsing simplu al datelor din Markdown
        date_str = "Necunoscută"
        targets = []
        stats = {}
        pkg_name = "Proiect"

        in_targets_section = False
        for line in md_text.split('\n'):
            line = line.strip()
            if line.startswith("## 2."):
                in_targets_section = True
                continue
            elif line.startswith("## 2b") or line.startswith("## 3"):
                in_targets_section = False
            if line.startswith("**Data generării:**"): date_str = line.replace("**Data generării:**", "").strip()
            elif line.startswith("**Data generarii:**"): date_str = line.replace("**Data generarii:**", "").strip()
            elif in_targets_section and line.startswith("|") and "Severitate" not in line and "---" not in line:
                parts = [p.strip().replace('`', '') for p in line.split('|') if p.strip()]
                if len(parts) >= 4: targets.append(parts)
            elif "Statistici pentru" in line: pkg_name = line.split("`")[1] if "`" in line else "Pachet"
            elif "* **Viteză:**" in line or "* **Viteza:**" in line: stats['speed'] = line.split(":")[-1].strip()
            elif "* **Total execuții:**" in line or "* **Total executii:**" in line: stats['execs'] = line.split(":")[-1].strip()
            elif "* **Stabilitate:**" in line: stats['stability'] = line.split(":")[-1].strip()
            elif "* **Crashes:**" in line: stats['crashes'] = line.split(":")[-1].replace('**', '').strip()

        # 2. Construirea Interfeței Grafice
        
        # --- HEADER ---
        header_frame = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        title_lbl = ctk.CTkLabel(header_frame, text="🛡️ Raport Analiză Securitate", font=ctk.CTkFont(size=28, weight="bold"))
        title_lbl.pack(anchor="w")
        
        date_lbl = ctk.CTkLabel(header_frame, text=f"Data generării: {date_str} | Target: {pkg_name}", text_color="gray60")
        date_lbl.pack(anchor="w")

        # --- SECTIUNEA 1: TARGET-URI (TABEL) ---
        t_title = ctk.CTkLabel(self.report_scroll, text="🎯 Ținte Identificate (The Scout)", font=ctk.CTkFont(size=18, weight="bold"))
        t_title.grid(row=1, column=0, sticky="w", pady=(10, 5))

        table_frame = ctk.CTkFrame(self.report_scroll)
        table_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        table_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Header Tabel
        headers = ["Pachet", "Funcție", "Fișier Sursă", "Severitate"]
        for col, text in enumerate(headers):
            lbl = ctk.CTkLabel(table_frame, text=text, font=ctk.CTkFont(weight="bold"), fg_color="gray25", corner_radius=3, pady=5)
            lbl.grid(row=0, column=col, sticky="ew", padx=2, pady=2)

        # Rânduri Tabel
        if not targets:
            lbl = ctk.CTkLabel(table_frame, text="Nu au fost găsite funcții vulnerabile.", text_color="gray50", pady=10)
            lbl.grid(row=1, column=0, columnspan=4)
        else:
            for row_idx, target in enumerate(targets, start=1):
                for col_idx, item in enumerate(target):
                    color = "gray20" if row_idx % 2 == 0 else "transparent"
                    lbl = ctk.CTkLabel(table_frame, text=item, fg_color=color, pady=5, font=ctk.CTkFont(family="Consolas", size=12))
                    lbl.grid(row=row_idx, column=col_idx, sticky="ew", padx=2, pady=1)

        # --- SECTIUNEA 2: STATISTICI THE HAMMER (CARDURI) ---
        s_title = ctk.CTkLabel(self.report_scroll, text="🔨 Validare Dinamică (The Hammer)", font=ctk.CTkFont(size=18, weight="bold"))
        s_title.grid(row=3, column=0, sticky="w", pady=(10, 5))

        if stats:
            cards_frame = ctk.CTkFrame(self.report_scroll, fg_color="transparent")
            cards_frame.grid(row=4, column=0, sticky="ew")
            cards_frame.grid_columnconfigure((0,1,2,3), weight=1)

            # Definim cardurile
            crash_color = "#dc3545" if stats.get('crashes', '0') != '0' else "#28a745" # Roșu dacă sunt crash-uri, Verde dacă e 0
            
            card_data = [
                ("Viteză Fuzzing", stats.get('speed', '0'), "#17a2b8"),     # Cyan
                ("Execuții Totale", stats.get('execs', '0'), "#007bff"),    # Albastru
                ("Stabilitate", stats.get('stability', '0%'), "#fd7e14"),   # Portocaliu
                ("Crashes Găsite", stats.get('crashes', '0'), crash_color)  # Dinamic
            ]

            for i, (title, value, color) in enumerate(card_data):
                card = ctk.CTkFrame(cards_frame, fg_color=color, corner_radius=10)
                card.grid(row=0, column=i, padx=10, pady=10, sticky="ew")
                
                v_lbl = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=24, weight="bold"), text_color="white")
                v_lbl.pack(pady=(15, 0))
                
                t_lbl = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color="white")
                t_lbl.pack(pady=(0, 15))
        else:
            # Sistem inteligent de decizie a erorii pentru raportul grafic
            if "V8" in md_text or "Node.js interne" in md_text or "napi_" in md_text.lower():
                # Alerta pentru module strâns cuplate de V8 (Culoare Mov/Indigo pentru "Arhitectură")
                alert_frame = ctk.CTkFrame(self.report_scroll, fg_color="#4B0082", corner_radius=8) 
                alert_frame.grid(row=4, column=0, sticky="ew", pady=10)
                
                alert_msg = "🧠 LIMITARE ARHITECTURALĂ IDENTIFICATĂ:\nProiectul folosește legături native N-API/V8. Fuzzer-ele C/C++ clasice necesită binare izolate, prin urmare, validarea dinamică a fost oprită inteligent. O analiză In-Process ar fi necesară."
                alert_lbl = ctk.CTkLabel(alert_frame, text=alert_msg, text_color="#E6E6FA", font=ctk.CTkFont(weight="bold", size=14), wraplength=700, justify="left", pady=15, padx=15)
                alert_lbl.pack(anchor="w")
            else:
                # Alerta generică pentru erori normale de compilare (Culoare Galben-Muștar)
                alert_frame = ctk.CTkFrame(self.report_scroll, fg_color="#856404", corner_radius=8)
                alert_frame.grid(row=4, column=0, sticky="ew", pady=10)
                
                alert_msg = "⚠️ Fuzzer-ul nu a putut fi rulat. Motiv probabil: Eșec la compilarea C++ sau fuzzer-ul a fost oprit de utilizator."
                alert_lbl = ctk.CTkLabel(alert_frame, text=alert_msg, text_color="#fff3cd", font=ctk.CTkFont(weight="bold"), wraplength=700, justify="left", pady=15, padx=15)
                alert_lbl.pack(anchor="w")

    
    def reset_steps_ui(self):
        for lbl in self.steps_ui:
            lbl.configure(text=lbl.cget("text").replace("✅", "⏳").replace("▶", "⏳"), fg_color="gray30")

    def update_step_ui(self, step_idx, status="active"):
        if step_idx >= len(self.steps_ui): return
        lbl = self.steps_ui[step_idx]
        current_text = lbl.cget("text").replace("⏳", "").replace("✅", "").replace("▶", "").strip()
        if status == "active": lbl.configure(text=f"▶ {current_text}", fg_color="#0056b3")
        elif status == "done": lbl.configure(text=f"✅ {current_text}", fg_color="#28a745")

    def toggle_scan(self):
        if not self.is_scanning:
            url = self.url_entry.get().strip()
            if not url: return self.results_textbox.insert("end", "[!] Eroare: Introdu URL valid.\n")
            try: minutes = float(self.time_entry.get())
            except ValueError: return self.results_textbox.insert("end", "[!] Eroare: Timp invalid.\n")

            self.is_scanning = True
            self.scan_btn.configure(text="⏹ Oprește Scanarea", fg_color="#dc3545", hover_color="#c82333")
            self.reset_steps_ui()
            self.results_textbox.delete("0.0", "end")
            self.results_textbox.insert("end", f"[*] Inițializare scanare pentru: {url} ({minutes} min)\n")
            self.tabview.set("Dashboard")

            threading.Thread(target=self.run_real_scan, args=(url, minutes), daemon=True).start()
        else:
            self.results_textbox.insert("end", "\n[!] Oprire de urgență...\n")
            self.is_scanning = False
            self.scan_btn.configure(text="▶ Start Scanare", fg_color="#28a745", hover_color="#218838", state="disabled")
            import subprocess
            threading.Thread(target=lambda: subprocess.run(["docker", "stop", "supply_fuzz_run"], capture_output=True), daemon=True).start()

    def run_real_scan(self, url, minutes):
        timeout_seconds = int(minutes * 60)

        def update_gui(message, progress=None):
            self.results_textbox.insert("end", message + "\n")
            self.results_textbox.see("end")
            
            if progress is not None:
                # FIX #4: mapare pe praguri (nu egalitate float).
                # Inceputul fiecaruia dintre cei 4 pasi:
                starts = [0.15, 0.40, 0.60, 0.80]
                for i, th in enumerate(starts):
                    if progress >= th:
                        self.update_step_ui(i, "active")
                    if i + 1 < len(starts) and progress >= starts[i + 1]:
                        self.update_step_ui(i, "done")
                if progress >= 1.0:
                    self.update_step_ui(3, "done")

        try:
            orch = Orchestrator(target_input=url, timeout=timeout_seconds, status_callback=update_gui)
            orch.run()
            
            # Caută ultimul raport (in subfoldere) și îl afișează automat
            reports = self._find_reports()
            if reports:
                latest_report = reports[0]
                with open(latest_report, 'r', encoding='utf-8') as f:
                    content = f.read()

                self.after(0, lambda c=content: self.render_beautiful_report(c))
                self.after(300, lambda: self.tabview.set("Raport Final"))

        except Exception as e:
            update_gui(f"[!] Eroare critică: {str(e)}", 0)
        finally:
            self.is_scanning = False
            self.after(0, lambda: self.scan_btn.configure(text="▶ Start Scanare", fg_color="#28a745", hover_color="#218838", state="normal"))
            self.after(0, self.load_history)

if __name__ == "__main__":
    app = SupplyFuzzApp()
    app.mainloop()