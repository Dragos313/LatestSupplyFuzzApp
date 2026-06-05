import argparse
import json
import sys
import shutil
import subprocess
from pathlib import Path

current_dir = Path(__file__).parent.resolve()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from resolver import NPMResolver, PyPIResolver
from scout import Scout
from bridge import Bridge
from hammer import Hammer

class Orchestrator:
    def __init__(self, target_input, timeout=3600, output_file="scan_report.json",
                 status_callback=None, use_dictionary=True):
        self.target_input = target_input
        self.timeout = timeout
        self.output_file = output_file
        self.workspace = (Path.cwd() / "fuzz_workspace").resolve()
        self.status_callback = status_callback
        self.use_dictionary = use_dictionary
        self.v8_detected = False

    def _log_status(self, message, progress=None):
        if "DETECTIE ARHITECTURALA" in message or "DETECȚIE ARHITECTURALĂ" in message:
            self.v8_detected = True
        if self.status_callback:
            self.status_callback(message, progress)
        else:
            print(message)

    def initialize_workspace(self):
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._log_status(f"[*] Spatiu de lucru pregatit la: {self.workspace}", 0.05)

    def _get_or_clone_repo(self):
        target_str = str(self.target_input).strip().rstrip("/")
        if target_str.startswith("http://") or target_str.startswith("https://"):
            repo_name = target_str.split("/")[-1].replace(".git", "")
            if not repo_name:
                repo_name = "repo_clonat"
            target_path = self.workspace / repo_name
            if not target_path.exists():
                self._log_status(f"[*] Descarc repo de pe GitHub: {target_str}...", 0.1)
                subprocess.run(["git", "clone", target_str, str(target_path)], capture_output=True)
            return target_path
        return Path(self.target_input).resolve()

    def _collect_native_packages(self, repo_path):
        native_pkgs = []

        self._log_status("[*] Pasul 0a: Rulare NPM Resolver...", 0.15)
        npm_resolver = NPMResolver(repo_path, self.workspace)
        npm_pkgs = npm_resolver.get_native_packages()
        if npm_pkgs:
            self._log_status(f"   [NPM] Gasite {len(npm_pkgs)} pachete native.", 0.18)
        native_pkgs.extend(npm_pkgs)

        self._log_status("[*] Pasul 0b: Rulare PyPI Resolver...", 0.20)
        pypi_resolver = PyPIResolver(repo_path, self.workspace)
        pypi_pkgs = pypi_resolver.get_native_packages()
        if pypi_pkgs:
            self._log_status(f"   [PyPI] Gasite {len(pypi_pkgs)} pachete native.", 0.23)
        native_pkgs.extend(pypi_pkgs)

        has_native_code = (
            any(repo_path.rglob("*.c")) or
            any(repo_path.rglob("*.cpp")) or
            any(repo_path.rglob("*.cc"))
        )
        if has_native_code:
            already_added = any(p.get("is_local_root") for p in native_pkgs)
            if not already_added:
                self._log_status("[*] Proiectul principal contine cod C/C++. Il adaugam la analiza!", 0.25)
                native_pkgs.append({
                    "name": repo_path.name,
                    "repo": str(self.target_input),
                    "ecosystem": "local",
                    "is_local_root": True
                })

        self._npm_resolver = npm_resolver
        self._pypi_resolver = pypi_resolver
        return native_pkgs

    def _clone_package(self, pkg):
        ecosystem = pkg.get("ecosystem", "npm")
        if ecosystem == "pypi":
            return self._pypi_resolver.clone_repository(pkg)
        else:
            return self._npm_resolver.clone_repository(pkg)

    def _ensure_in_workspace(self, pkg, source_dir):
        """
        FIX: Hammer monteaza DOAR self.workspace in container (/fuzz_target).
        Daca sursa unui pachet local-root e in afara workspace-ului, o copiem
        in workspace/<name> ca sa fie vizibila la compilare/fuzzing.
        """
        source_dir = Path(source_dir).resolve()
        dest = (self.workspace / pkg['name']).resolve()
        try:
            inside = self.workspace in source_dir.parents or source_dir == self.workspace
        except Exception:
            inside = False
        if inside:
            return source_dir
        if not dest.exists():
            self._log_status(f"[*] Copiez sursa '{pkg['name']}' in workspace pentru fuzzing...")
            shutil.copytree(source_dir, dest, dirs_exist_ok=True)
        return dest

    @staticmethod
    def _score_target(harness_info):
        """Scor euristic pentru a alege cel mai bun entry-point de fuzzat:
        preferam harness-ul oficial libFuzzer, apoi API-uri publice de parsing,
        si penalizam functiile interne (init/alloc/util/conversii)."""
        name = harness_info['function_name']
        low = name.lower()
        if name == "LLVMFuzzerTestOneInput":
            return 10000
        score = 0
        # transformatoare in-place (minify/transform): OOB clasic
        if any(k in low for k in ['minify', 'transform', 'compact', 'normalize']):
            score += 120
        if any(k in low for k in ['parse', 'decode', 'load', 'read',
                                  'deserial', 'unmarshal', 'scan', 'decompress']):
            score += 100
        if low.startswith('_') or any(k in low for k in [
                'internal', 'realloc', 'alloc', 'init', 'util', 'helper',
                'to_ucs', 'to_utf', 'hex', 'free', 'dup']):
            score -= 80
        return score

    def run(self):
        self.initialize_workspace()
        self.repo_path = self._get_or_clone_repo()

        native_pkgs = self._collect_native_packages(self.repo_path)
        if not native_pkgs:
            self._log_status("[-] Nu s-au gasit pachete native sau cod C/C++. Oprire.", 1.0)
            return

        self._log_status(f"[+] Total pachete de analizat: {len(native_pkgs)}", 0.30)

        # Pasul 1: The Scout
        self._log_status("[*] Pasul 1: Analiza Statica (The Scout)...", 0.40)
        all_targets = []
        for pkg in native_pkgs:
            ecosystem_label = pkg.get("ecosystem", "npm").upper()
            self._log_status(f"   [Scout/{ecosystem_label}] Analizez: {pkg['name']}")

            if pkg.get("is_local_root"):
                source_dir = self.repo_path
            else:
                source_dir = self._clone_package(pkg)

            source_dir = self._ensure_in_workspace(pkg, source_dir)

            scout_engine = Scout(source_dir)
            targets = scout_engine.analyze()
            for t in targets:
                t['package_name'] = pkg['name']
                t['ecosystem'] = pkg.get('ecosystem', 'npm')
                all_targets.append(t)

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(all_targets, f, indent=4)

        entrypoints = [t for t in all_targets if t.get("kind", "entrypoint") == "entrypoint"]
        findings = [t for t in all_targets if t.get("kind") == "finding"]
        harnessable = [t for t in entrypoints if t.get("harnessable", True)]
        skipped = len(entrypoints) - len(harnessable)

        if not all_targets:
            self._log_status("[-] The Scout nu a gasit nimic relevant in cod.", 1.0)
            return

        msg = (f"[+] Scout: {len(harnessable)} entry-points fuzzabile "
               f"({len(entrypoints)} detectate, {skipped} ne-harnessabile C++/custom), "
               f"{len(findings)} constatari statice.")
        self._log_status(msg, 0.55)

        harnesses = []
        if harnessable:
            # Pasul 2: The Bridge
            self._log_status("[*] Pasul 2: Generare Harness-uri + Seed-uri (The Bridge)...", 0.60)
            bridge_engine = Bridge(self.output_file, self.workspace)
            harnesses = bridge_engine.generate_harnesses()

        if harnesses:
            # Pasul 3: The Hammer. Alegem cel mai bun entry-point dupa scor
            # (libFuzzer oficial > API public de parsing > restul).
            chosen = max(harnesses, key=self._score_target)
            self._log_status(
                f"[+] Pasul 3: Lansare 'The Hammer' pe {chosen['function_name']} "
                f"(Limita: {self.timeout}s)...", 0.80
            )
            hammer_engine = Hammer(self.workspace)
            hammer_engine.build_container()
            hammer_engine.run_fuzzing(
                package_name=chosen['package_name'],
                harness_file=chosen['harness'],
                timeout_seconds=self.timeout,
                log_callback=lambda msg: self._log_status(msg, progress=None),
                use_dictionary=self.use_dictionary
            )
            fuzzed_pkg = chosen['package_name']
            fuzzed_func = chosen['function_name']
        else:
            if entrypoints and not harnessable:
                self._log_status(
                    f"[!] {len(entrypoints)} functii detectate sunt metode C++/cu tipuri "
                    "custom (ne-harnessabile cu abordarea extern \"C\"). "
                    "Sar peste fuzzing; raportez doar analiza statica.", 0.80
                )
            else:
                self._log_status(
                    "[!] Niciun entry-point fuzzabil. Sar peste fuzzing, "
                    "generez raport doar cu constatarile statice.", 0.80
                )
            fuzzed_pkg = entrypoints[0]['package_name'] if entrypoints else (
                findings[0]['package_name'] if findings else 'unknown'
            )
            fuzzed_func = None

        # Pasul 4: The Reporter (ruleaza intotdeauna)
        self._log_status("[+] Pasul 4: Generare raport final...", 0.90)
        from reporter import Reporter
        reporter_engine = Reporter(self.output_file, self.workspace, v8_detected=self.v8_detected, use_dictionary=self.use_dictionary)
        raport_final = reporter_engine.generate_final_report(fuzzed_package=fuzzed_pkg, fuzzed_function=fuzzed_func)

        self._log_status(f"\nProiect finalizat!\nRaportul tau este aici: {raport_final}", 1.0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Supply-Fuzz Orchestrator")
    parser.add_argument("--repo", required=True, help="Calea catre folderul proiectului sau URL GitHub")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--output", default="scan_report.json")
    args = parser.parse_args()

    orch = Orchestrator(args.repo, args.timeout, args.output)
    orch.run()