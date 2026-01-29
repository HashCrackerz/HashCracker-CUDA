### Nota:

Questa versione contiene script e porting per **AMD HIP**, il branch [main](https://github.com/HashCrackerz/HashCracker/tree/main) contiene la versione CUDA originale.

---
<p align="left">
  <img width="150" alt="logo" src="https://github.com/user-attachments/assets/73297594-3581-4afd-ad0b-39d4bc0e66bf" />
</p>

# HashCracker
## _Parallel SHA-256 Brute Force & Dictionary (salted) Password Cracker_


![alt text](https://img.shields.io/badge/Language-C++%20%7C%20CUDA-green)

![alt text](https://img.shields.io/badge/Platform-NVIDIA%20(CUDA)-blue) 

![alt text](https://img.shields.io/badge/Algorithm-SHA256-purple)

Progetto per il corso di Sistemi di Elaborazione Accelerata della facoltà di Ingegneria Informatica Magistrale di UniBo.
Applicazione **parallela** per il cracking di password tramite attacco Brute Force su hash SHA-256 (anche salted) e attacco a dizionario, 
con confronto prestazionale tra implementazione Sequenziale (CPU) e Parallela (GPU/CUDA).

## 📝 Descrizione
Il progetto implementa un **cracker di password** che supporta diverse modalità di attacco per invertire hash SHA-256. 
L'obiettivo principale è dimostrare lo speedup ottenibile passando da un'esecuzione seriale su CPU a un'esecuzione 
massivamente parallela su GPU, analizzando diverse strategie di ottimizzazione della memoria CUDA (Global vs Constant 
Memory) e delle risorse di calcolo.

## ⚙️ Funzionalità
- **Brute Force Incrementale**: Generazione dinamica di password dato un charset e un range di lunghezza (min-max).
- **Attacco a Dizionario**: Supporto per wordlist esterne.
- **Supporto Salt**: Gestione di hash saltati (Brute Force e attacco a dizionario).
- **Multi-Platform**: Codice nativo CUDA per **NVIDIA** e script di porting (semi) automatico per **AMD** HIP.

## 📂 Struttura del Progetto
- `Sequenziale/`: Implementazione **sequenziale** di riferimento (usa [OpenSSL](https://openssl-library.org/)).
- `CUDA_NAIVE/`: **Prima implementazione GPU** (uso memoria globale).
- `CUDAv1/`: Ottimizzazione memoria (uso Constant Memory per charset e target).
- `CUDAv2/`: Ottimizzazione kernel (loop unrolling, register optimization per SHA-256).
- `UTILS/`: Funzioni di supporto (I/O file, parsing argomenti).
- `SHA256_CUDA/`: implementazione **CUDA per SHA256**, basata sull'implementazione di [mochimodev](https://github.com/mochimodev/cuda-hashing-algos/blob/master/sha256.cu).
- `SHA256_CUDA_OPT/`: implementazione **CUDA ottimizzata per SHA256** (usato da CUDAv2).
- `ESTENSIONE/`: contiene l'implementazione delle'estensione del progetto, ossia l'attacco a dizionario e l'hash cracking con salt.
- `convert_to_hip.ps1` (branch [`amd-port`](https://github.com/HashCrackerz/HashCracker/tree/amd-port/HashCracker)): Script PowerShell per il **porting automatico** su AMD ROCm/HIP.
- `kernel_[versione_progetto].cu`: file per eseguire la corrispondente versione.
Tutte le versioni CUDA[versione_progetto] (eseguite dai rispettivi file kernel) hanno come dipendenza i file di
`UTILS` e `SHA256_CUDA`, ad eccezione della CUDAv2 che usa `SHA256_CUDA_OPT` invece di `SHA256_CUDA`.

Il kernel CUDA estensione ha le stesse depiendenze della v2 (inclusa) a cui si aggiunge quanto contenuto nella cartella `ESTENSIONE`.

Per la versione AMD (RDNA) con HIP si può sostanzialmente utilizzare il medesimo codice NVIDIA, eseguendo lo script di 
porting, il quale si occupa di tradurre opportunamente le funzioni, i tipi e importare le diverse librerie, oltre che
convertire ad esempio gli import con i doppo apici in parentesi angolari. I file vengono sovrascritti e rinominati, ma la
 struttura progettuale resta la medesima. Una conversione funzionante si trova nel branch [`amd-port`](https://github.com/HashCrackerz/HashCracker/tree/amd-port/HashCracker).

## 🛠️ Requisiti
- Hardware:
  - **GPU NVIDIA** (Compute Capability 5.0+)
  - Opzionale per HIP: **GPU AMD**

- Software:
  - NVIDIA **CUDA Toolkit** (11.0+)
  - **OpenSSL** (per l'implementazione CPU)
  - **Compilatore C++** (MSVC su Windows, GCC/Clang su Linux)
  - **PowerShell** (per lo script di porting)
  - **ROCm** (per compilare con hipcc e per l'ambiente AMD).
 
## 🚀 Compilazione

### NVIDIA CUDA
Assicurarsi di avere le librerie OpenSSL linkate correttamente.
```powershell
nvcc -arch=sm_89 -rdc=true -O3 \
    kernel_naive.cu \
    CUDA_NAIVE/*.cu \
    SHA256_CUDA/*.cu \
    UTILS/*.cu UTILS/*.cpp \
    -o naive_cuda \
    -lssl -lcrypto -lcudadevrt -I.
```
_(cambiare i nomi dei file e delle dipendenze in base alla versione da compilare)_

### AMD HIP (Porting)
Il progetto include uno script per convertire automaticamente il codice CUDA in HIP.
1. Eseguire lo script di conversione:
   ```powershell
   .\convert_to_hip.ps1
   ```
2. Compilare con hipcc (esempio per Windows):
   ```powershell
   hipcc -fgpu-rdc -O3 -std=c++14 --offload-arch=native `
      kernel_naive.cu `
      HIP_NAIVE/hip_naive.cu `
      SHA256_HIP/sha256.cu `
      UTILS/hip_utils.cu `
      UTILS/utils.cpp `
      -I. -I./HIP_NAIVE -I./SHA256_HIP -I./UTILS `
      -I"D:\OpenSSL-Win64\include" `
      -L"D:\OpenSSL-Win64\lib\VC\x64\MTd" `
      -l libcrypto.lib `
      -D_CRT_SECURE_NO_WARNINGS `
      -o naive_amd.exe
   ```

   _(cambiare i nomi dei file e delle dipendenze in base alla versione da compilare)_

## 💻 Utilizzo
Il programma accetta i parametri da riga di comando per la massima flessibilità:
```cmd
./brute_force_cuda [<blockSize>] <hash_target> <min_len> <max_len> <file_charset> [<dizionario-si/no> <file_dizionario>]
```
La `blockSize` va passata sempre e solo negli script paralleli su gpu (sia CUDA che HIP).
Il dizionario (flag e file path) va passato solo negli script estensione.

Esempio:

Cercare la password dell'hash (corrispondente a "qwerty") con lunghezza 6, usando il charset standard:
```cmd
./brute_force_cuda 256 qwerty 1 6 ASSETS/CharSet.txt No
```

## 📊 Analisi delle Performance
I test sono stati condotti su:
- sequenziale e AMD: desktop con Ryzen 9 9900X e RX 9070XT
- CUDA: NVIDIA RTX 4060 Laptop e parzialmente Google Colab

### Approfondimento Tecnico: Analisi
L'algoritmo SHA-256 è fortemente **Compute-Bound**. L'implementazione v2 utilizza pesantemente i registri per mantenere lo stato 
dell'hash ed evitare latenze di memoria locale/globale. Sebbene l'alto numero di registri (118) limiti il numero di warp attivi 
(bassa occupancy), la velocità di esecuzione del singolo thread aumenta drasticamente. In questo scenario, massimizzare l'IPC 
(Instructions Per Cycle) si è rivelato più efficace che massimizzare il parallelismo a livello di latenza (Occupancy).

Inoltre, l'utilizzo di dimensioni del blocco minori (64/128 thread) ha portato a performance migliori rispetto ai classici 256, 
grazie a una migliore gestione della Tail Effect (quantizzazione delle wave) e minore overhead di scheduling.

## 👥 Autori
- [Andrea Vitale](https://github.com/WHYUBM)
- [Matteo Fontolan](https://github.com/itsjustwhitee)

## 📜 Licenza
Questo progetto è distribuito sotto licenza AGPL. Vedi il file `LICENSE` per i dettagli.
