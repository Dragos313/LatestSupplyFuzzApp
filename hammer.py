import subprocess
import re
from pathlib import Path

# Coduri ANSI de culoare generate de AFL++ pentru terminal (ex: \x1b[1;94m = albastru bold).
# GUI-ul nu le interpreteaza, asa ca le eliminam.
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

class Hammer:
    def __init__(self, workspace):
        self.workspace = Path(workspace).resolve()
        self.docker_image = "supply-fuzz-hammer"
        self.app_dir = Path(__file__).parent.resolve()
        self.container_name = "supply_fuzz_run"

    def build_container(self):
        subprocess.run(
            ["docker", "build", "-t", self.docker_image, str(self.app_dir)],
            check=True,
            capture_output=True
        )

    def run_fuzzing(self, package_name, harness_file, timeout_seconds=60,
                    log_callback=None, use_dictionary=True):
        harness_name = Path(harness_file).name

        subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True)

        # Include-uri comune (acopera si addon-uri Node N-API).
        INCLUDES = ("-I. -Isrc -Iinclude "
                    "-I/usr/include/node "
                    "-I/opt/node_headers/node_modules/node-addon-api "
                    "-I/opt/node_headers/node_modules/nan")

        # ---------------------------------------------------------------------
        # FIX #5 (esential): compilam sursele .c cu compilatorul C (afl-clang-fast)
        # si .cc/.cpp cu cel C++ (afl-clang-fast++), apoi le legam. Altfel sursele
        # C compilate ca C++ au nume "mangled" si harness-ul (extern "C") nu se
        # leaga -> "undefined reference". Sarim si fisierele cu 'main' propriu.
        # Fuzzing-ul porneste DOAR daca binarul a fost produs efectiv.
        # ---------------------------------------------------------------------
        container_cmd = f"""
set -u
cd /fuzz_target/{package_name} || {{ echo '[-] Folderul pachetului lipseste.'; exit 1; }}
mkdir -p out objs

if [ ! -d in ] || [ -z "$(ls -A in 2>/dev/null)" ]; then
  mkdir -p in && echo 'default_seed' > in/seed.txt
  echo '[*] Seed fallback creat (Bridge nu a generat seed-uri).'
else
  echo "[*] Folosesc $(ls in | wc -l) seed-uri inteligente generate de Bridge."
fi

OBJS=""
compile_one() {{
  f="$1"
  if grep -Eq '\\bmain[ \\t]*\\(' "$f"; then echo "[*] skip (are main): $f"; return; fi
  o="objs/$(echo "$f" | tr '/.' '__').o"
  ext="${{f##*.}}"
  if [ "$ext" = "c" ]; then
    if afl-clang-fast -c -fsanitize=address -g "$f" -o "$o" {INCLUDES} 2>/dev/null; then
      OBJS="$OBJS $o"
    else echo "[*] skip (nu compileaza C): $f"; fi
  else
    if afl-clang-fast++ -std=c++17 -c -fsanitize=address -g "$f" -o "$o" {INCLUDES} 2>/dev/null; then
      OBJS="$OBJS $o"
    else echo "[*] skip (nu compileaza C++): $f"; fi
  fi
}}

echo '[*] Incepere compilare surse...'
for f in $(find . -maxdepth 4 -type f -name '*.c' \\
    ! -path '*/test/*' ! -path '*/tests/*' \\
    ! -path '*/example/*' ! -path '*/examples/*' \\
    ! -path '*/benchmark*/*' ! -path '*/third_party/*' \\
    ! -path '*/node_modules/*' ! -path '*/.git/*'); do compile_one "$f"; done
for f in $(find . -maxdepth 4 -type f \\( -name '*.cc' -o -name '*.cpp' \\) \\
    ! -path '*/test/*' ! -path '*/tests/*' \\
    ! -path '*/example/*' ! -path '*/examples/*' \\
    ! -path '*/benchmark*/*' ! -path '*/third_party/*' \\
    ! -path '*/node_modules/*' ! -path '*/.git/*'); do compile_one "$f"; done

echo '[*] Compilare harness...'
if ! afl-clang-fast++ -std=c++17 -c -fsanitize=address -g /fuzz_target/{harness_name} -o objs/_harness.o {INCLUDES}; then
  echo '[!] Harness-ul nu compileaza. Fuzzing sarit.'
fi

if [ -f objs/_harness.o ]; then
  if afl-clang-fast++ -fsanitize=address $OBJS objs/_harness.o -o fuzzed_binary 2>link_err.txt; then
    echo '[+] Compilare + link reusite.'
  else
    echo '[!] Link esuat:'; head -20 link_err.txt
  fi
fi

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_NO_UI=1

DICT_ARG=""
if {"true" if use_dictionary else "false"} && [ -f ./afl_tokens.dict ]; then
  DICT_ARG="-x ./afl_tokens.dict"
  echo "[*] Dictionar hibrid ACTIV: $(grep -c '^kw_' ./afl_tokens.dict) tokeni (-x)."
else
  echo "[*] Dictionar hibrid INACTIV (rulare baseline)."
fi

if [ -f ./fuzzed_binary ]; then
  echo '[*] Incepe fuzzing-ul hibrid cu seed-uri inteligente...'
  afl-fuzz -V {timeout_seconds} -m none $DICT_ARG -i in -o out ./fuzzed_binary @@
else
  echo '[-] Binarul nu exista, fuzzing sarit.'
fi
"""

        process = subprocess.Popen([
            "docker", "run", "--rm", "-i", "--name", self.container_name,
            "-v", f"{self.workspace}:/fuzz_target",
            self.docker_image, "bash", "-c", container_cmd
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           text=True, bufsize=1, encoding='utf-8', errors='replace')

        v8_reported = False
        for line in process.stdout:
            clean_line = _ANSI_RE.sub('', line).strip()
            if not clean_line:
                continue

            if "undefined reference to `napi_" in clean_line or "Napi::" in clean_line:
                if not v8_reported:
                    msg = ("[!] DETECTIE ARHITECTURALA: Acest modul foloseste functii "
                           "Node.js (V8) interne. (napi_)")
                    if log_callback: log_callback(msg)
                    else: print(msg)
                    v8_reported = True
                continue

            if "clang: error: linker command failed" in clean_line:
                continue

            if log_callback: log_callback(f"   [Hammer] {clean_line}")
            else: print(f"   [Hammer] {clean_line}")

        process.wait()