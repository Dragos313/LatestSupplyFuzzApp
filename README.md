# Supply-Fuzz

**Automated vulnerability discovery for the native software supply chain** — a fully automated hybrid pipeline that combines targeted static analysis with coverage-guided fuzzing to find memory-safety bugs in the C/C++ dependencies buried inside NPM and PyPI packages.

Given only a repository URL, Supply-Fuzz goes from dependency resolution to a confirmed, proof-of-concept vulnerability **with zero manual steps** — no hand-written harnesses, no manual sanitizer setup, no seed engineering.

> Developed as a master's dissertation ("Automated Vulnerability Discovery using Hybrid Fuzzing and Static Analysis in Modern Software Supply Chains", Ovidius University of Constanța).

---

## The Problem

Modern applications are assembled from hundreds of transitive dependencies, many of which wrap native C/C++ code (`sharp`, `bcrypt`, `sqlite3`, `numpy`, `lxml`, …). The moment execution crosses into that native layer, the memory-safety guarantees of the host runtime disappear — reintroducing buffer overflows, use-after-free, and integer-overflow defects into otherwise "safe" applications.

Existing tooling leaves a gap:

| Approach | Limitation |
| --- | --- |
| **Registry scanners** (Snyk, Dependabot) | Only detect *known* CVEs — blind to zero-days. |
| **Static analysis (SAST)** | Scales well but produces a high false-positive rate; cannot confirm exploitability. |
| **Fuzzing (AFL++)** | Zero false positives, but needs a hand-written harness per function — infeasible at supply-chain scale. |

**Supply-Fuzz** closes this gap by automating the entire discovery lifecycle and, critically, by feeding static-analysis knowledge back into the fuzzer to guide it.

---

## How It Works

```
   ┌──────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌───────────┐
   │ Resolver │ ─▶│  Scout  │ ─▶│  Bridge  │ ─▶│  Hammer  │ ─▶│ Reporter  │
   └──────────┘   └─────────┘   └──────────┘   └──────────┘   └───────────┘
    NPM / PyPI     Semgrep        Harness +       AFL++ in       CVSS + PoC +
    crawl +        AST scan +     hybrid dict +   Docker +       Markdown
    clone          harnessability seed corpus     AddressSan.    report
```

1. **Resolver** — crawls NPM (`package-lock.json`) and PyPI (`requirements.txt`, `pyproject.toml`) manifests, isolates native dependencies, and clones their sources. Directly-submitted C/C++ repos are supported too.
2. **Scout** — runs Semgrep with custom Rego-style rules to find fuzzable entry points and dangerous sinks (CWE-120, 122, 134, 416, 476, 190). A **harnessability classifier** decides which functions can be compiled into a harness without external headers.
3. **Bridge** — the core innovation. It auto-synthesises a C++ harness (`extern "C"`), a **function-aware seed corpus**, and a **hybrid semantic dictionary**: string literals and parser keywords lifted from the target's own source, fed to AFL++ via `-x` so it generates valid mutations from the first cycle.
4. **Hammer** — compiles and fuzzes inside an **ephemeral Docker container** with LLVM edge-coverage instrumentation and AddressSanitizer. A fault-tolerant two-pass compilation strategy handles mixed C/C++ trees.
5. **Reporter** — parses AFL++ telemetry, collects crash artifacts, estimates CVSS v3.1 severity, and emits a timestamped Markdown security report with proof-of-concept files.

The whole pipeline is exposed through a dark-themed desktop **GUI** (CustomTkinter) with live progress indicators and an interactive report viewer.

---

## Key Innovation — The Hybrid Semantic Dictionary

A parser's source code implicitly encodes the grammar of its accepted input. Supply-Fuzz extracts those string literals and keywords during static analysis and injects them into AFL++'s mutation engine, so the fuzzer explores *semantically valid* inputs from the very first execution — instead of blindly rediscovering the input format. **Static analysis directly steers dynamic fuzzing.**

---

## Results

Validated on three production C parser libraries (**cJSON, tomlc99, parson**) across eight controlled sessions:

| Metric | Result |
| --- | --- |
| Real vulnerability confirmed autonomously | **CVE-2019-11835** (`cJSON_Minify`, heap-buffer-overflow), CVSS 7.5 |
| Crash variants, hybrid vs. baseline (5-min budget) | **13 vs. 10** (+30%) |
| Early-phase discovery (first 500 executions) | **9 vs. 3** (3× advantage) |
| Time from URL to PoC report | **under 5 minutes**, zero manual steps |
| False positives on patched libraries | **0** |

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- Python 3.10+
- [Semgrep](https://semgrep.dev/docs/getting-started/) (`pip install semgrep`)
- Git

The AFL++ / LLVM / AddressSanitizer toolchain is provisioned automatically inside the Docker container — no manual setup required on the host.

---

## Getting Started

```bash
# 1. Clone the repo
git clone https://github.com/Dragos313/LatestSupplyFuzzApp.git
cd LatestSupplyFuzzApp

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build the fuzzing container (installs AFL++, LLVM, ASan)
docker build -t supply-fuzz .

# 4. Launch the GUI
python main.py
```

In the dashboard, paste a GitHub URL (or a local path), set a fuzzing duration, toggle the hybrid dictionary, and press **Start**. The four pipeline stages light up as they run, and the final report appears in the **Report** tab.

> To reproduce the flagship result, point it at a pre-patch cJSON release (`v1.7.14`) and watch it confirm CVE-2019-11835 autonomously.

---

## Project Structure

```
.
├── orchestrator.py        # Central pipeline controller
├── resolver.py            # NPM / PyPI dependency crawler
├── scout.py               # Semgrep static analysis + harnessability classifier
├── scout_logic.yaml       # Semgrep rules (entry points + CWE sinks)
├── bridge.py              # Harness + hybrid dictionary + seed synthesis
├── hammer.py              # AFL++ in Docker + AddressSan.
├── reporter.py            # CVSS estimation + Markdown report generation
├── main.py                # CustomTkinter GUI 
├── Dockerfile             # AFL++ / LLVM / ASan fuzzing container
├── requirements.txt
└── README.md

# generated at runtime (git-ignored):
├── fuzz_workspace/        # cloned repos, harnesses, dictionaries, corpora, crashes
└── scans_history/         # timestamped reports + proof_of_concept/ artifacts
```

---

## Responsible Use

Supply-Fuzz is a **defensive security research tool**, intended for testing software you own or are authorised to test, and for responsible disclosure of any findings to upstream maintainers. It discovers memory-safety defects so they can be fixed — not exploited. Do not use it against systems or codebases you do not have permission to audit, and follow coordinated disclosure practices for any new vulnerabilities you find.

The proof-of-concept artifacts it produces are minimal crash-triggering inputs for reproduction and triage; this repository intentionally ships no weaponised exploit code.

---

## Roadmap

- **LLM-assisted harness synthesis** for complex C++ / N-API functions currently excluded by the harnessability classifier.
- **UBSan alongside ASan** to dynamically confirm integer-overflow (CWE-190) sinks.
- **Stack-trace crash deduplication** (ClusterFuzz-style) to collapse variants of one root cause.
- **Distributed / parallel fuzzing** and **Kubernetes orchestration** for continuous, CI-triggered supply-chain auditing.
- **Extended ecosystems**: Cargo, Maven (JNI), RubyGems.

---

## Author

**Dragoș-Andrei Pană** — MSc Cyber Security & Machine Learning, Ovidius University of Constanța
pana749@gmail.com

---

## License

Released under the [MIT License](LICENSE).
