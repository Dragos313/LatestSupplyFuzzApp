import subprocess
import json
import sys
import os
import re
import shutil
import platform
from pathlib import Path

class Scout:
    # Tipuri primitive C/C++ pe care le putem declara intr-un harness fara headere.
    PRIMITIVE_TYPES = {
        "char", "signed char", "unsigned char", "short", "unsigned short",
        "int", "unsigned int", "unsigned", "long", "unsigned long",
        "long long", "unsigned long long", "size_t", "ssize_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "float", "double", "bool", "void", "wchar_t", "char16_t", "char32_t",
        "intptr_t", "uintptr_t", "byte", "u_char",
    }

    def __init__(self, target_path):
        self.target_path = Path(target_path).resolve()
        self.rules_path = self._locate_rules()
        self.is_windows = platform.system() == "Windows"

    # -------------------------------------------------------------------------
    # FIX #1: cautam fisierul de reguli in mai multe locatii.
    # -------------------------------------------------------------------------
    def _locate_rules(self):
        here = Path(__file__).parent
        candidates = [
            here / "rules" / "scout_logic.yaml",
            here / "scout_logic.yaml",
            here.parent / "scout_logic.yaml",
            Path.cwd() / "scout_logic.yaml",
        ]
        for c in candidates:
            if c.exists():
                return c.resolve()
        return (here / "scout_logic.yaml").resolve()

    def _find_semgrep(self):
        found = shutil.which("semgrep")
        if found:
            return found
        if self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            possible_dirs = [
                Path(appdata) / "Python" / "Python312" / "Scripts",
                Path(appdata) / "Python" / "Python311" / "Scripts",
                Path(appdata) / "Python" / "Python310" / "Scripts",
                Path(sys.executable).parent / "Scripts",
                Path("C:/Python312/Scripts"),
                Path("C:/Python311/Scripts"),
                Path(localappdata) / "Packages" /
                "PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0" /
                "LocalCache" / "local-packages" / "Python312" / "Scripts",
                Path(localappdata) / "Packages" /
                "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0" /
                "LocalCache" / "local-packages" / "Python311" / "Scripts",
            ]
            for d in possible_dirs:
                candidate = d / "semgrep.exe"
                if candidate.exists():
                    return str(candidate)
        else:
            for d in [Path(sys.executable).parent, Path.home() / ".local" / "bin",
                      Path("/usr/local/bin"), Path("/usr/bin")]:
                candidate = d / "semgrep"
                if candidate.exists():
                    return str(candidate)
        return None

    # -------------------------------------------------------------------------
    # FIX #2 (NOU): extragem numele functiei + argumentele DIRECT din sursa,
    # la linia raportata de semgrep. Nu mai depindem de metavariabila $FUNC sau
    # de campul "lines" (care la unele versiuni semgrep e mascat "requires login").
    # -------------------------------------------------------------------------
    def _extract_signature(self, file_path, start_line):
        """
        Returneaza (func_name, args_list, is_static).
        Gaseste primul ')' urmat de '{' (inceputul corpului functiei), apoi merge
        inapoi la '(' pereche (echilibrat) si ia identificatorul dinaintea ei.
        Robust la 'extern "C" {', macro-uri de export si paranteze imbricate.
        """
        try:
            text = Path(file_path).read_text(encoding='utf-8', errors='replace')
        except Exception:
            return None, [], False
        lines = text.splitlines()
        if start_line < 1 or start_line > len(lines):
            return None, [], False

        window = "\n".join(lines[start_line - 1: start_line - 1 + 60])

        body = re.search(r'\)\s*(?:const)?\s*\{', window)
        if not body:
            return None, [], False
        rp = window.rindex(')', 0, body.start() + 1)

        # mergem inapoi pana la '(' pereche
        depth = 0
        i = rp
        while i >= 0:
            if window[i] == ')':
                depth += 1
            elif window[i] == '(':
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        if i < 0:
            return None, [], False
        lp = i

        args_str = window[lp + 1: rp]

        # identificatorul de dinaintea lui '('
        j = lp - 1
        while j >= 0 and window[j].isspace():
            j -= 1
        end = j + 1
        while j >= 0 and (window[j].isalnum() or window[j] in "_:~"):
            j -= 1
        func_name = window[j + 1: end]
        if "::" in func_name:
            func_name = func_name.split("::")[-1]
        if not func_name:
            return None, [], False

        args_list = self._split_args(args_str)
        if len(args_list) == 1 and args_list[0].replace(" ", "") in ("void", ""):
            args_list = []

        prefix = window[max(0, j - 120): j + 1]
        is_static = bool(re.search(r'(^|\W)(static|inline)(\W|$)', prefix))

        return func_name, args_list, is_static

    @staticmethod
    def _split_args(raw):
        """Split pe virgule de la nivelul de sus (ignora <...> si (...))."""
        args, buf, depth = [], "", 0
        for ch in raw:
            if ch in "<(":
                depth += 1; buf += ch
            elif ch in ">)":
                depth -= 1; buf += ch
            elif ch == ',' and depth == 0:
                if buf.strip():
                    args.append(buf.strip())
                buf = ""
            else:
                buf += ch
        if buf.strip():
            args.append(buf.strip())
        return args

    @classmethod
    def _is_harnessable(cls, args_list):
        """
        Returneaza True doar daca TOATE tipurile argumentelor sunt primitive,
        adica putem genera un harness care compileaza fara headere externe.
        Astfel eliminam metodele C++ cu tipuri custom (Parent*, Callback,
        napi_env, v8::Local<...>) care altfel produc harness-uri ne-compilabile.
        """
        for a in args_list:
            t = a.replace("*", " ").replace("&", " ").replace("const", " ")
            toks = t.split()
            if len(toks) >= 2:
                toks = toks[:-1]          # eliminam numele parametrului
            type_str = " ".join(toks).strip()
            if not type_str:
                continue
            if type_str not in cls.PRIMITIVE_TYPES:
                return False
        return True

    def analyze(self):
        if not self.target_path.exists():
            return []
        if not self.rules_path.exists():
            print(f"[!] Scout: nu am gasit fisierul de reguli la {self.rules_path}")
            return []

        files = list(self.target_path.rglob("*.[ch]*"))
        print(f"[*] Scout analizeaza {len(files)} fisiere sursa in {self.target_path}")

        semgrep_bin = self._find_semgrep()
        if not semgrep_bin:
            print("[!] Scout: semgrep nu a fost gasit. Instalati cu: pip install semgrep")
            return []

        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["PATH"] = str(Path(semgrep_bin).parent) + os.pathsep + env.get("PATH", "")

        cmd = [semgrep_bin, "--config", str(self.rules_path),
               "--json", "--quiet", "--no-git-ignore", str(self.target_path)]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', env=env)
            if not result.stdout.strip():
                if result.stderr:
                    print(f"[!] Scout stderr: {result.stderr[:300]}")
                return []

            data = json.loads(result.stdout)
            entrypoints, findings = [], []

            for match in data.get("results", []):
                extra = match.get("extra", {})
                metadata = extra.get("metadata", {}) or {}
                kind = metadata.get("target_kind", "finding")
                rule_id = match.get("check_id", "unknown")
                if "." in rule_id:
                    rule_id = rule_id.split(".")[-1]
                severity = extra.get("severity", "WARNING")
                message = extra.get("message", "")
                path = match.get("path")
                line = match.get("start", {}).get("line", 0)

                func_name, args_list, is_static = self._extract_signature(path, line)

                if kind == "entrypoint":
                    if not func_name:
                        continue
                    # Harnessabil doar daca: tipuri primitive, NU static/inline,
                    # si definit intr-un fisier C (.c/.h) — functiile din .cpp/.cc
                    # au nume C++ "mangled" si nu se leaga prin extern "C".
                    is_cpp = str(path).lower().endswith(
                        (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx"))
                    harnessable = (self._is_harnessable(args_list)
                                   and not is_static and not is_cpp)
                    entrypoints.append({
                        "kind": "entrypoint",
                        "function_name": func_name,
                        "file": path, "line": line,
                        "package_path": str(self.target_path),
                        "signature_args": args_list,
                        "harnessable": harnessable,
                        "is_static": is_static,
                        "rule_id": rule_id, "severity": severity,
                    })
                else:
                    findings.append({
                        "kind": "finding",
                        "function_name": func_name or "(sink)",
                        "file": path, "line": line,
                        "package_path": str(self.target_path),
                        "rule_id": rule_id, "severity": severity,
                        "message": message,
                    })

            uniq_ep = list({e['function_name']: e for e in entrypoints}.values())
            uniq_fd = list({(f['file'], f['line'], f['rule_id']): f for f in findings}.values())
            return uniq_ep + uniq_fd

        except json.JSONDecodeError as e:
            print(f"[!] Scout: raspuns JSON invalid de la semgrep: {e}")
            return []
        except Exception as e:
            print(f"[!] Eroare Scout: {e}")
            return []