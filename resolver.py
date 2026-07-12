import json
import subprocess
import requests
from pathlib import Path

class NPMResolver:
    def __init__(self, project_path, workspace):
        self.project_path = Path(project_path)
        self.lock_file = self.project_path / "package-lock.json"
        self.workspace = Path(workspace)

    def get_native_packages(self):
        if not self.lock_file.exists():
            print(f"[-] Nu am găsit package-lock.json în {self.project_path}")
            return []

        native_keywords = ['sqlite3', 'sharp', 'bcrypt', 'canvas', 'node-gyp', 'leveldown',
                           'fsevents', 'node-sass', 'grpc', 'sodium-native', 'cpu-features']
        found_packages = []

        with open(self.lock_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            packages = data.get("packages", {})
            for name, info in packages.items():
                if not name: continue
                clean_name = name.split("node_modules/")[-1]
                if any(k in clean_name for k in native_keywords):
                    found_packages.append({
                        "name": clean_name,
                        "version": info.get("version"),
                        "repo": self._fetch_repo_url(clean_name),
                        "ecosystem": "npm"
                    })
        return found_packages

    def _fetch_repo_url(self, pkg_name):
        try:
            r = requests.get(f"https://registry.npmjs.org/{pkg_name}", timeout=10)
            return r.json().get("repository", {}).get("url", "").replace("git+", "").replace(".git", "")
        except:
            return None

    def clone_repository(self, pkg_info):
        target_dir = self.workspace / pkg_info['name']
        if not target_dir.exists():
            print(f"[*] Clonare {pkg_info['name']}...")
            subprocess.run(["git", "clone", "--depth", "1", pkg_info['repo'], str(target_dir)],
                           capture_output=True)
        return target_dir


# =============================================================================
# Detectează pachete Python cu extensii native C/C++ (via setup.py sau
# pyproject.toml care conțin ext_modules sau cffi/cython).
# Acoperă un vector important din supply chain-ul modern Python.
# =============================================================================
class PyPIResolver:
    def __init__(self, project_path, workspace):
        self.project_path = Path(project_path)
        self.workspace = Path(workspace)

        # Indicatori că un pachet Python are extensii native
        self.native_indicators = [
            'cffi', 'cython', 'pybind11', 'ctypes',
            'ext_modules', 'Extension(', 'build_ext',
            'cryptography', 'pillow', 'numpy', 'lxml',
            'psycopg2', 'msgpack', 'ujson', 'orjson',
            'pycurl', 'greenlet', 'gevent', 'regex'
        ]

    def get_native_packages(self):
        """
        Detectează pachete native din:
        1. requirements.txt — lista de dependințe directe
        2. setup.py / pyproject.toml — dacă proiectul însuși are extensii native
        """
        found = []
        found.extend(self._scan_requirements())
        found.extend(self._scan_setup_files())
        return found

    def _scan_requirements(self):
        """Caută în requirements.txt pachete cunoscute ca native."""
        req_files = list(self.project_path.glob("requirements*.txt"))
        found = []

        for req_file in req_files:
            try:
                lines = req_file.read_text(encoding='utf-8', errors='replace').splitlines()
            except Exception:
                continue

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Extragem numele pachetului (ignorăm versiunea)
                pkg_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('[')[0].strip().lower()

                if any(ind.lower() in pkg_name for ind in self.native_indicators):
                    repo_url = self._fetch_pypi_repo_url(pkg_name)
                    if repo_url:
                        found.append({
                            "name": pkg_name,
                            "version": None,
                            "repo": repo_url,
                            "ecosystem": "pypi"
                        })
                        print(f"   [PyPI Resolver] Găsit pachet nativ: {pkg_name} → {repo_url}")

        return found

    def _scan_setup_files(self):
        """
        Verifică dacă proiectul în sine conține extensii C native
        (ext_modules în setup.py sau [tool.cython] în pyproject.toml).
        """
        found = []
        setup_py = self.project_path / "setup.py"
        pyproject = self.project_path / "pyproject.toml"

        files_to_check = [f for f in [setup_py, pyproject] if f.exists()]

        for f in files_to_check:
            content = f.read_text(encoding='utf-8', errors='replace')
            if any(ind in content for ind in ['ext_modules', 'Extension(', 'pybind11', 'cffi', 'cython']):
                print(f"   [PyPI Resolver] Proiectul însuși conține extensii native ({f.name}).")
                # Returnăm proiectul curent ca target
                found.append({
                    "name": self.project_path.name,
                    "version": None,
                    "repo": None,
                    "ecosystem": "pypi",
                    "is_local_root": True
                })
                break  # Nu duplicăm dacă e găsit în ambele fișiere

        return found

    def _fetch_pypi_repo_url(self, pkg_name):
        """Obține URL-ul de GitHub de la PyPI JSON API."""
        try:
            r = requests.get(f"https://pypi.org/pypi/{pkg_name}/json", timeout=10)
            if r.status_code != 200:
                return None
            info = r.json().get("info", {})

            # Căutăm în project_urls pentru GitHub
            project_urls = info.get("project_urls") or {}
            for key, url in project_urls.items():
                if "github.com" in (url or ""):
                    return url.rstrip("/")

            # Fallback: home_page
            home = info.get("home_page", "") or ""
            if "github.com" in home:
                return home.rstrip("/")

        except Exception:
            pass
        return None

    def clone_repository(self, pkg_info):
        """Clonează sursa pachetului în workspace."""
        target_dir = self.workspace / pkg_info['name']
        if not target_dir.exists() and pkg_info.get('repo'):
            print(f"[*] Clonare PyPI {pkg_info['name']}...")
            subprocess.run(["git", "clone", "--depth", "1", pkg_info['repo'], str(target_dir)],
                           capture_output=True)
        return target_dir