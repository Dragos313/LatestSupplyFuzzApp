import json
import shutil
from pathlib import Path
from datetime import datetime

class Reporter:
    def __init__(self, scan_report_path, workspace, v8_detected=False, use_dictionary=True):
        self.report_path = Path(scan_report_path)
        self.use_dictionary = use_dictionary
        self.workspace = Path(workspace)
        self.v8_detected = v8_detected

    def _get_fuzzer_stats(self, package_name):
        stats_path = self.workspace / package_name / "out" / "default" / "fuzzer_stats"
        stats = {}
        if stats_path.exists():
            with open(stats_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if ':' in line:
                        key, val = line.split(':', 1)
                        stats[key.strip()] = val.strip()
        return stats

    @staticmethod
    def _format_duration(stats):
        """Durata efectiva a fuzzing-ului, din fuzzer_stats AFL++."""
        secs = None
        try:
            if stats.get('run_time'):
                secs = int(float(stats['run_time']))
            elif stats.get('last_update') and stats.get('start_time'):
                secs = int(float(stats['last_update']) - float(stats['start_time']))
        except (ValueError, TypeError):
            secs = None
        if secs is None or secs < 0:
            return "N/A"
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def _collect_crashes(self, package_name, report_dir):
        crashes_src = self.workspace / package_name / "out" / "default" / "crashes"
        poc_dir = report_dir / "proof_of_concept"

        if not crashes_src.exists():
            return []

        crash_files = [f for f in crashes_src.iterdir() if f.is_file() and f.name != "README.txt"]
        if not crash_files:
            return []

        poc_dir.mkdir(parents=True, exist_ok=True)

        crashes_info = []
        for i, crash_file in enumerate(crash_files):
            raw = crash_file.read_bytes()
            preview_hex = raw[:64].hex()
            preview_printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:64])

            dest_name = f"crash_{i+1:03d}_{crash_file.name}.bin"
            dest_path = poc_dir / dest_name
            shutil.copy2(crash_file, dest_path)

            crash_type = "UNKNOWN"
            # Windows inlocuieste ':' (interzis in numele de fisier) cu U+F03A din
            # zona Unicode privata. AFL scrie 'sig:06', dar pe disc devine 'sig\uf03a06'.
            # Normalizam inapoi la ':' (plus fullwidth ':' U+FF1A, intalnit pe unele
            # configuratii) ca sa potrivim corect semnalul. Acceptam si separatorul '_'.
            fname = (crash_file.name.lower()
                     .replace('\uf03a', ':')
                     .replace('\uff1a', ':'))
            if "sig:06" in fname or "sig_06" in fname:
                crash_type = "SIGABRT (Heap Corruption / Assert)"
            elif "sig:11" in fname or "sig_11" in fname:
                crash_type = "SIGSEGV (Segmentation Fault)"
            elif "sig:07" in fname or "sig_07" in fname:
                crash_type = "SIGBUS (Bus Error)"
            elif "sig:08" in fname or "sig_08" in fname:
                crash_type = "SIGFPE (Floating Point / Div-by-Zero)"
            elif "asan" in fname:
                crash_type = "AddressSanitizer (Buffer Overflow / UAF)"

            crashes_info.append({
                "index": i + 1,
                "original_name": crash_file.name,
                "poc_file": str(dest_path),
                "size_bytes": len(raw),
                "crash_type": crash_type,
                "preview_hex": preview_hex,
                "preview_ascii": preview_printable,
            })
        return crashes_info

    def _estimate_cvss(self, crash_type, func_name, crashes_count):
        """Euristica simplificata CVSS v3.1 (nu este un calcul oficial)."""
        if crashes_count == 0:
            return "N/A", "gray"

        base_vector = "AV:N/AC:L/PR:N/UI:N/S:U"

        if "Segmentation Fault" in crash_type or "Buffer Overflow" in crash_type:
            score = 8.1; impact = "C:H/I:H/A:H"
        elif "Heap Corruption" in crash_type:
            score = 7.5; impact = "C:H/I:L/A:H"
        elif "Floating Point" in crash_type:
            score = 5.3; impact = "C:N/I:N/A:H"
        else:
            score = 6.5; impact = "C:L/I:L/A:H"

        if any(kw in func_name.lower() for kw in ['parse', 'read', 'load', 'decode']):
            score = min(score + 0.5, 10.0)

        color = "#dc3545" if score >= 7.0 else ("#fd7e14" if score >= 4.0 else "#28a745")
        full_vector = f"CVSS:3.1/{base_vector}/{impact}"
        return f"{score:.1f} ({full_vector})", color

    def generate_final_report(self, fuzzed_package=None):
        if not self.report_path.exists():
            return "Eroare: Nu s-a gasit raportul de scanare."

        with open(self.report_path, 'r', encoding='utf-8') as f:
            targets = json.load(f)

        entrypoints = [t for t in targets if t.get("kind", "entrypoint") == "entrypoint"]
        findings = [t for t in targets if t.get("kind") == "finding"]
        harnessable = [t for t in entrypoints if t.get("harnessable", True)]
        skipped = len(entrypoints) - len(harnessable)

        # Pachetul pe care a rulat efectiv fuzzing-ul
        if fuzzed_package:
            pkg_name = fuzzed_package
        elif entrypoints:
            pkg_name = entrypoints[0].get('package_name', 'unknown')
        elif targets:
            pkg_name = targets[0].get('package_name', 'unknown')
        else:
            pkg_name = 'unknown'

        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_dir = Path("scans_history") / f"{timestamp}_{pkg_name}"
        report_dir.mkdir(parents=True, exist_ok=True)

        crashes_info = self._collect_crashes(pkg_name, report_dir)
        stats = self._get_fuzzer_stats(pkg_name)

        report_md = "# Raport Analiza Securitate Supply-Fuzz\n"
        report_md += f"**Data generarii:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        # 1. Rezumat executiv
        report_md += "## 1. Rezumat Executiv\n"
        report_md += (f"Analiza automata a identificat **{len(harnessable)}** functii fuzzabile "
                      f"si compilabile (entry-points), din **{len(entrypoints)}** detectate "
                      f"(**{skipped}** ne-harnessabile: metode C++ / tipuri custom), "
                      f"**{len(findings)}** constatari statice si "
                      f"**{len(crashes_info)}** crash-uri confirmate.\n\n")

        # 2. Entry-points (doar cele compilabile)
        report_md += "## 2. Detalii Target-uri Identificate\n"
        report_md += "| Pachet | Functie | Fisier | Severitate |\n| :--- | :--- | :--- | :--- |\n"
        if harnessable:
            for t in harnessable:
                pkg = t.get('package_name', 'N/A')
                func = t.get('function_name', 'N/A')
                path = t.get('file', t.get('path', 'N/A'))
                report_md += f"| {pkg} | `{func}` | `{path}` | MEDIUM |\n"
        else:
            report_md += "| - | (niciun entry-point compilabil) | - | - |\n"
        if skipped > 0:
            report_md += (f"\n> Nota: {skipped} functii au fost detectate ca potentiale "
                          "entry-points dar omise fiindca folosesc tipuri C++/custom "
                          "ne-declarabile in harness (ex: binding-uri N-API).\n")

        # 2b. Constatari statice (sink-uri)
        report_md += "\n## 2b. Constatari Statice (Sink-uri / CWE)\n"
        if findings:
            report_md += "| Pachet | Regula | Fisier:Linie | Severitate |\n| :--- | :--- | :--- | :--- |\n"
            for t in findings:
                pkg = t.get('package_name', 'N/A')
                rule = t.get('rule_id', 'N/A')
                loc = f"{t.get('file','?')}:{t.get('line','?')}"
                sev = t.get('severity', 'WARNING')
                report_md += f"| {pkg} | `{rule}` | `{loc}` | {sev} |\n"
        else:
            report_md += "*Nu au fost identificate sink-uri statice.*\n"

        # 3. Statistici fuzzer
        report_md += "\n## 3. Rezultate Validare Dinamica (The Hammer)\n"
        dict_path = self.workspace / pkg_name / "afl_tokens.dict"
        if dict_path.exists() and self.use_dictionary:
            try:
                n_tok = sum(1 for ln in dict_path.read_text(encoding="utf-8",
                            errors="replace").splitlines() if ln.startswith("kw_"))
            except Exception:
                n_tok = 0
            report_md += f"* **Dictionar hibrid (static->fuzz):** {n_tok} tokeni extrasi din sursa\n"
        if stats:
            cvg = stats.get('bitmap_cvg', 'N/A')
            corpus = stats.get('corpus_count', stats.get('paths_total', 'N/A'))
            duration = self._format_duration(stats)
            report_md += f"### Statistici pentru `{pkg_name}`\n"
            dict_used = self.use_dictionary and dict_path.exists()
            report_md += f"* **Dictionar:** {'ACTIV (hibrid)' if dict_used else 'INACTIV (baseline)'}\n"
            report_md += f"* **Durata fuzzing:** {duration}\n"
            report_md += f"* **Acoperire (coverage):** {cvg}\n"
            report_md += f"* **Elemente corpus (corpus_count):** {corpus}\n"
            report_md += f"* **Viteza:** {stats.get('execs_per_sec', '0')} exec/sec\n"
            report_md += f"* **Total executii:** {stats.get('execs_done', '0')}\n"
            report_md += f"* **Stabilitate:** {stats.get('stability', '0%')}\n"
            report_md += f"* **Crashes:** **{stats.get('saved_crashes', stats.get('unique_crashes', '0'))}**\n"
        else:
            report_md += "*Nota: Statisticile de fuzzing nu au putut fi recuperate.*\n"

        # 4. Crashes + PoC
        report_md += "\n## 4. Crash-uri Confirmate & Proof-of-Concept\n"
        if crashes_info:
            ref_func = entrypoints[0].get('function_name', 'unknown') if entrypoints else 'unknown'
            for c in crashes_info:
                cvss_score, _ = self._estimate_cvss(c['crash_type'], ref_func, len(crashes_info))
                report_md += f"\n### Crash #{c['index']}: `{c['crash_type']}`\n"
                report_md += f"* **Tip semnal:** `{c['crash_type']}`\n"
                report_md += f"* **Marime input:** {c['size_bytes']} bytes\n"
                report_md += f"* **CVSS Estimat:** {cvss_score}\n"
                report_md += f"* **Fisier PoC:** `{c['poc_file']}`\n"
                report_md += f"* **Preview HEX (primii 64B):** `{c['preview_hex']}`\n"
                report_md += f"* **Preview ASCII:** `{c['preview_ascii']}`\n"
        else:
            report_md += "*Nu au fost identificate crash-uri in aceasta sesiune de fuzzing.*\n"

        if self.v8_detected:
            report_md += ("\n\n> DETECTIE ARHITECTURALA: Acest modul foloseste functii "
                          "Node.js (V8) interne. (napi_)\n")

        final_path = report_dir / "report.md"
        with open(final_path, 'w', encoding='utf-8') as f:
            f.write(report_md)

        if crashes_info:
            with open(report_dir / "crashes.json", 'w', encoding='utf-8') as f:
                json.dump(crashes_info, f, indent=4)

        return final_path.absolute()