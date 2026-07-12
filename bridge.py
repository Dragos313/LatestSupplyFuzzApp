import json
import re
import struct
from pathlib import Path

class Bridge:
    def __init__(self, scan_report_path, workspace):
        self.report_path = Path(scan_report_path)
        self.workspace = Path(workspace)

    def generate_harnesses(self):
        """
        Returneaza o lista de dictionare:
            {"harness": Path, "package_name": str, "function_name": str}
        Genereaza harness DOAR pentru target-urile de tip 'entrypoint'.
        """
        if not self.report_path.exists():
            return []
        with open(self.report_path, 'r', encoding='utf-8') as f:
            targets = json.load(f)

        generated = []
        dict_done = set()
        for target in targets:
            # FIX #2: ignoram sink-urile (findings). Doar entry-points devin harness.
            if target.get("kind", "entrypoint") != "entrypoint":
                continue
            # Sarim peste semnaturile ne-compilabile (tipuri C++ custom).
            if not target.get("harnessable", True):
                continue

            h_path = self._write_harness(target)
            if h_path:
                self._generate_smart_seeds(target)
                # Dictionar AFL derivat din analiza statica a sursei (o data per pachet)
                pkg = target['package_name']
                if pkg not in dict_done:
                    self._generate_dictionary(target)
                    dict_done.add(pkg)
                generated.append({
                    "harness": h_path,
                    "package_name": target['package_name'],
                    "function_name": target['function_name'],
                })
        return generated

    # -------------------------------------------------------------------------
    # DICTIONAR AFL (componenta HIBRIDA: analiza statica -> fuzzing dinamic)
    # Extrage tokeni (siruri literale, cuvinte-cheie de parsing) din codul sursa
    # al tintei si ii scrie ca dictionar AFL (-x). Acesti tokeni ajuta fuzzer-ul
    # sa treaca de verificari structurale (ex: 'true', 'null', '{', '}', chei).
    # -------------------------------------------------------------------------
    _STOP_WORDS = {b"software", b"as is", b"copyright", b"warranty",
                   b"the", b"and", b"for"}

    def _generate_dictionary(self, target, max_tokens=256):
        package_name = target['package_name']
        src_dir = Path(target.get('package_path') or (self.workspace / package_name))
        if not src_dir.exists():
            src_dir = self.workspace / package_name
        if not src_dir.exists():
            return None

        exclude = ("/test", "/tests", "/example", "/benchmark",
                   "/third_party", "/node_modules", "/.git")
        lit_re = re.compile(r'"((?:\\.|[^"\\])*)"')
        seen = {}

        files = [f for f in src_dir.rglob("*.[ch]*")
                 if not any(e in str(f).replace("\\", "/").lower() for e in exclude)]
        for f in files[:200]:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in lit_re.findall(text):
                try:
                    val = bytes(m, "utf-8").decode("unicode_escape").encode("latin-1", "replace")
                except Exception:
                    val = m.encode("utf-8", "replace")
                if not (1 <= len(val) <= 24):
                    continue
                if re.search(rb'\s', val):                      # fara spatii/newline
                    continue
                if b'%' in val:                                 # fara format strings
                    continue
                if val.lower().endswith((b'.h', b'.c', b'.cpp', b'.hpp', b'.cc')):
                    continue
                if val.lower() in self._STOP_WORDS:
                    continue
                if not re.search(rb'[A-Za-z0-9{}\[\]:,]', val):
                    continue
                seen[val] = seen.get(val, 0) + 1

        tokens = [t for t, _ in sorted(seen.items(), key=lambda kv: -kv[1])[:max_tokens]]
        if not tokens:
            return None

        dict_path = self.workspace / package_name / "afl_tokens.dict"
        dict_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dict_path, "w", encoding="utf-8") as fh:
            fh.write("# Dictionar AFL generat din analiza statica a sursei (Supply-Fuzz Bridge)\n")
            for i, tok in enumerate(tokens):
                fh.write(f'kw_{i:03d}="{self._afl_escape(tok)}"\n')

        print(f"   [Bridge] Dictionar hibrid: {len(tokens)} tokeni -> {dict_path}")
        return dict_path

    @staticmethod
    def _afl_escape(b):
        """Escapeaza un sir de bytes pentru formatul de dictionar AFL."""
        out = []
        for byte in b:
            ch = chr(byte)
            if ch == '\\':
                out.append('\\\\')
            elif ch == '"':
                out.append('\\"')
            elif 32 <= byte < 127:
                out.append(ch)
            else:
                out.append(f'\\x{byte:02x}')
        return "".join(out)

    # -------------------------------------------------------------------------
    # SEED GENERATION INTELIGENTA
    # -------------------------------------------------------------------------
    def _generate_smart_seeds(self, target):
        func_name = target['function_name']
        package_name = target['package_name']
        args_list = target.get('signature_args', [])

        seed_dir = self.workspace / package_name / "in"
        seed_dir.mkdir(parents=True, exist_ok=True)

        (seed_dir / "seed_empty.bin").write_bytes(b"\x00")

        args_combined = " ".join(args_list).lower()

        if 'char' in args_combined and '*' in args_combined:
            self._write_string_seeds(seed_dir, func_name)

        if ('uint8' in args_combined or 'byte' in args_combined or 'void' in args_combined) \
                and ('size' in args_combined or 'len' in args_combined):
            self._write_binary_seeds(seed_dir, func_name)

        if any(kw in func_name.lower() for kw in ['parse', 'read', 'load', 'decode', 'deserializ']):
            self._write_format_seeds(seed_dir, func_name)

        if any(kw in func_name.lower() for kw in ['decompress', 'inflate', 'uncompress', 'unzip']):
            self._write_compression_seeds(seed_dir)

        self._write_boundary_seeds(seed_dir)

        print(f"   [Bridge] Seed-uri inteligente generate pentru {func_name} in {seed_dir}")

    def _write_string_seeds(self, seed_dir, func_name):
        seeds = {
            "seed_str_normal.bin":      b"hello_world",
            "seed_str_empty.bin":       b"",
            "seed_str_null_mid.bin":    b"hello\x00world",
            "seed_str_long.bin":        b"A" * 1024,
            "seed_str_fmt.bin":         b"%s%s%s%n%n%n",
            "seed_str_special.bin":     b"../../../etc/passwd",
            "seed_str_unicode.bin":     "\u3053\u3093\u306b\u3061\u306f".encode('utf-8'),
            "seed_str_newlines.bin":    b"line1\r\nline2\nline3",
        }
        for name, data in seeds.items():
            (seed_dir / name).write_bytes(data)

    def _write_binary_seeds(self, seed_dir, func_name):
        seeds = {
            "seed_bin_zeros.bin":        b"\x00" * 64,
            "seed_bin_ones.bin":         b"\xff" * 64,
            "seed_bin_pattern.bin":      bytes(range(256)),
            "seed_bin_size_zero.bin":    b"",
            "seed_bin_int_overflow.bin": struct.pack("<I", 0xFFFFFFFF) + b"\x41" * 8,
            "seed_bin_neg_size.bin":     struct.pack("<i", -1) + b"\x41" * 8,
        }
        for name, data in seeds.items():
            (seed_dir / name).write_bytes(data)

    def _write_format_seeds(self, seed_dir, func_name):
        seeds = {
            "seed_json_valid.bin":     b'{"key": "value", "num": 42}',
            "seed_json_empty.bin":     b'{}',
            "seed_json_deep.bin":      b'{"a":{"b":{"c":{"d":{"e":{"f":{}}}}}}}',
            "seed_json_large_str.bin": b'{"key": "' + b"A" * 4096 + b'"}',
            "seed_xml_valid.bin":      b'<?xml version="1.0"?><root><item>test</item></root>',
            "seed_xml_entity.bin":     b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xx "test">]><x>&xx;</x>',
            "seed_xml_bomb.bin":       b'<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY lol "lol">]><x>&lol;</x>',
        }
        for name, data in seeds.items():
            (seed_dir / name).write_bytes(data)

    def _write_compression_seeds(self, seed_dir):
        zlib_header = b'\x78\x9c'
        seeds = {
            "seed_zlib_header_only.bin": zlib_header,
            "seed_zlib_corrupted.bin":   zlib_header + b"\xff\xff\xff\xff",
            "seed_zlib_truncated.bin":   zlib_header + b"\x01\x02",
        }
        for name, data in seeds.items():
            (seed_dir / name).write_bytes(data)

    def _write_boundary_seeds(self, seed_dir):
        seeds = {
            "seed_boundary_1byte.bin":     b"\x41",
            "seed_boundary_maxuint16.bin": struct.pack("<H", 0xFFFF),
            "seed_boundary_maxuint32.bin": struct.pack("<I", 0xFFFFFFFF),
            "seed_boundary_maxuint64.bin": struct.pack("<Q", 0xFFFFFFFFFFFFFFFF),
            "seed_boundary_offbyone.bin":  b"A" * 255,
            "seed_boundary_offbyone2.bin": b"A" * 257,
        }
        for name, data in seeds.items():
            (seed_dir / name).write_bytes(data)

    # -------------------------------------------------------------------------
    # HARNESS GENERATION
    # -------------------------------------------------------------------------
    def _write_harness(self, target):
        func_name = target['function_name']
        package_name = target['package_name']
        args_list = target.get('signature_args', [])

        args_definition = ", ".join(args_list)
        if not args_definition:
            args_definition = "const uint8_t *data, size_t size"

        call_params = []
        for arg in args_list:
            arg_lower = arg.lower()
            if '*' in arg:
                if 'char' in arg_lower:
                    call_params.append("(char *)buf")
                else:
                    call_params.append("(uint8_t *)buf")
            elif 'size' in arg_lower or 'len' in arg_lower:
                call_params.append("len")
            else:
                call_params.append("0")

        call_params_str = ", ".join(call_params)
        if not call_params_str:
            call_params_str = "buf, len"

        harness_filename = f"harness_{package_name}_{func_name}.cpp"
        harness_path = self.workspace / harness_filename
        self.workspace.mkdir(parents=True, exist_ok=True)

        harness_code = f"""
        #include <stdint.h>
        #include <stddef.h>
        #include <stdio.h>
        #include <stdlib.h>

        extern "C" int {func_name}({args_definition});

        int main(int argc, char **argv) {{
            if (argc < 2) return 1;

            FILE *f = fopen(argv[1], "rb");
            if (!f) return 1;

            fseek(f, 0, SEEK_END);
            size_t len = ftell(f);
            fseek(f, 0, SEEK_SET);

            uint8_t *buf = (uint8_t *)malloc(len + 1);
            if (!buf) {{ fclose(f); return 1; }}

            if (fread(buf, 1, len, f) != len) {{ /* tolerate short read */ }}
            buf[len] = '\\0';
            fclose(f);

            {func_name}({call_params_str});

            free(buf);
            return 0;
        }}
        """
        with open(harness_path, 'w', encoding='utf-8') as f:
            f.write(harness_code)
        return harness_path