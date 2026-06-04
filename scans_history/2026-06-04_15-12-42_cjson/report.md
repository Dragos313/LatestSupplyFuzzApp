# Raport Analiza Securitate Supply-Fuzz
**Data generarii:** 2026-06-04 15:12:42

## 1. Rezumat Executiv
Analiza automata a identificat **2** functii fuzzabile si compilabile (entry-points), din **7** detectate (**5** ne-harnessabile: metode C++ / tipuri custom), **41** constatari statice si **0** crash-uri confirmate.

## 2. Detalii Target-uri Identificate
| Pachet | Functie | Fisier | Severitate |
| :--- | :--- | :--- | :--- |
| cjson | `cJSON_ParseWithLength` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c` | MEDIUM |
| cjson | `LLVMFuzzerTestOneInput` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\cjson_read_fuzzer.c` | MEDIUM |

> Nota: 5 functii au fost detectate ca potentiale entry-points dar omise fiindca folosesc tipuri C++/custom ne-declarabile in harness (ex: binding-uri N-API).

## 2b. Constatari Statice (Sink-uri / CWE)
| Pachet | Regula | Fisier:Linie | Severitate |
| :--- | :--- | :--- | :--- |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:127` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:204` | WARNING |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:363` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:461` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:566` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:614` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:618` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:623` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:629` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:976` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1017` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1063` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1280` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1440` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1449` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1458` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:1478` | WARNING |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON.c:2020` | WARNING |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:77` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:234` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:245` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:804` | WARNING |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:1122` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:1188` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:1203` | ERROR |
| cjson | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\cJSON_Utils.c:1248` | ERROR |
| cjson | `use-after-free-pattern` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:69` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:95` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:97` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:98` | ERROR |
| cjson | `use-after-free-pattern` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:163` | ERROR |
| cjson | `use-after-free-pattern` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\afl.c:168` | ERROR |
| cjson | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\cjson_read_fuzzer.c:62` | WARNING |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\fuzz_main.c:17` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\fuzz_main.c:38` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\fuzzing\fuzz_main.c:44` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\test.c:61` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\test.c:70` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\test.c:76` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\test.c:78` | ERROR |
| cjson | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\cjson\test.c:93` | ERROR |

## 3. Rezultate Validare Dinamica (The Hammer)
* **Dictionar hibrid (static->fuzz):** 29 tokeni extrasi din sursa
### Statistici pentru `cjson`
* **Dictionar:** ACTIV (hibrid)
* **Acoperire (coverage):** 0.37%
* **Elemente corpus (corpus_count):** 26
* **Viteza:** 45750.00 exec/sec
* **Total executii:** 183
* **Stabilitate:** 100.00%
* **Crashes:** **0**

## 4. Crash-uri Confirmate & Proof-of-Concept
*Nu au fost identificate crash-uri in aceasta sesiune de fuzzing.*
