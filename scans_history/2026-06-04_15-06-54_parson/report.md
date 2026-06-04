# Raport Analiza Securitate Supply-Fuzz
**Data generarii:** 2026-06-04 15:06:54

## 1. Rezumat Executiv
Analiza automata a identificat **1** functii fuzzabile si compilabile (entry-points), din **21** detectate (**20** ne-harnessabile: metode C++ / tipuri custom), **4** constatari statice si **0** crash-uri confirmate.

## 2. Detalii Target-uri Identificate
| Pachet | Functie | Fisier | Severitate |
| :--- | :--- | :--- | :--- |
| parson | `json_value_init_string_with_len` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\parson\parson.c` | MEDIUM |

> Nota: 20 functii au fost detectate ca potentiale entry-points dar omise fiindca folosesc tipuri C++/custom ne-declarabile in harness (ex: binding-uri N-API).

## 2b. Constatari Statice (Sink-uri / CWE)
| Pachet | Regula | Fisier:Linie | Severitate |
| :--- | :--- | :--- | :--- |
| parson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\parson\parson.c:281` | WARNING |
| parson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\parson\parson.c:756` | WARNING |
| parson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\parson\parson.c:902` | WARNING |
| parson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\parson\parson.c:1930` | WARNING |

## 3. Rezultate Validare Dinamica (The Hammer)
* **Dictionar hibrid (static->fuzz):** 52 tokeni extrasi din sursa
### Statistici pentru `parson`
* **Viteza:** 164.21 exec/sec
* **Total executii:** 49266
* **Stabilitate:** 100.00%
* **Crashes:** **0**

## 4. Crash-uri Confirmate & Proof-of-Concept
*Nu au fost identificate crash-uri in aceasta sesiune de fuzzing.*
