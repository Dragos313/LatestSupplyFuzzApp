# Raport Analiza Securitate Supply-Fuzz
**Data generarii:** 2026-06-04 15:00:43

## 1. Rezumat Executiv
Analiza automata a identificat **2** functii fuzzabile si compilabile (entry-points), din **14** detectate (**12** ne-harnessabile: metode C++ / tipuri custom), **61** constatari statice si **0** crash-uri confirmate.

## 2. Detalii Target-uri Identificate
| Pachet | Functie | Fisier | Severitate |
| :--- | :--- | :--- | :--- |
| tomlc99 | `toml_utf8_to_ucs` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c` | MEDIUM |
| tomlc99 | `toml_parse` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c` | MEDIUM |

> Nota: 12 functii au fost detectate ca potentiale entry-points dar omise fiindca folosesc tipuri C++/custom ne-declarabile in harness (ex: binding-uri N-API).

## 2b. Constatari Statice (Sink-uri / CWE)
| Pachet | Regula | Fisier:Linie | Severitate |
| :--- | :--- | :--- | :--- |
| tomlc99 | `signed-unsigned-comparison` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c:70` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c:73` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c:87` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c:416` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml.c:429` | WARNING |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:52` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:69` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:79` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:82` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:85` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:88` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:91` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:94` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:97` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:104` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:141` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:155` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:165` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:196` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:202` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:217` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:222` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:228` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:233` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:241` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:271` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:277` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:294` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_cat.c:298` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:41` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:44` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:47` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:50` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:53` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:56` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:59` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:77` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:79` | ERROR |
| tomlc99 | `unsafe-string-copy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:90` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:107` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:120` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:125` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:137` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:144` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:149` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:158` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:185` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:189` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_json.c:202` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_sample.c:47` | ERROR |
| tomlc99 | `format-string-vulnerability` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\toml_sample.c:54` | ERROR |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:13` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:19` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:25` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:31` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:37` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:43` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:49` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:55` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:61` | WARNING |
| tomlc99 | `unsafe-memcpy` | `D:\Facultate\CSML\Disertatie\newapp\fuzz_workspace\tomlc99\unittest\t1.c:67` | WARNING |

## 3. Rezultate Validare Dinamica (The Hammer)
* **Dictionar hibrid (static->fuzz):** 27 tokeni extrasi din sursa
### Statistici pentru `tomlc99`
* **Viteza:** 163.56 exec/sec
* **Total executii:** 49070
* **Stabilitate:** 100.00%
* **Crashes:** **0**

## 4. Crash-uri Confirmate & Proof-of-Concept
*Nu au fost identificate crash-uri in aceasta sesiune de fuzzing.*
