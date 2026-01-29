# se non parte: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Write-Host "ATTENZIONE: Questo script convertirà tutti i file CUDA in HIP nella cartella corrente." -ForegroundColor Red
Write-Host "I file originali verranno sovrascritti/rinominati."
$confirmation = Read-Host "Sei sicuro di voler procedere? (s/N)"

# Correzione logica: usa una regex per accettare s o S
if ($confirmation -notmatch "^[sS]$") { 
    Write-Host "Operazione annullata."
    exit 
}

# Configurazione estensioni file
$extensions = @("*.cu", "*.cuh", "*.cpp", "*.h", "*.c")

# Lista delle sostituzioni
# NOTA: L'ordine è importante. Prima le cose specifiche (header), poi le parole generiche.
$replacements = @(
    @{ Old = "<cuda_runtime.h>"; New = "<hip/hip_runtime.h>" },
    @{ Old = "#include <device_launch_parameters.h>"; New = "// #include <device_launch_parameters.h>" },
    @{ Old = "cuda"; New = "hip" },
    @{ Old = "CUDA"; New = "HIP" },
    @{ Old = "nvcc"; New = "hipcc" }
)

# Prendi tutti i file ricorsivamente
$files = Get-ChildItem -Recurse -Include $extensions

foreach ($file in $files) {
    # Salta lo script stesso o cartelle git
    if ($file.FullName -match "git" -or $file.Name -eq "convert_to_hip.ps1") { continue }

    $content = Get-Content $file.FullName -Raw
    $originalContent = $content

    foreach ($pair in $replacements) {
        # -creplace è fondamentale: è CASE SENSITIVE. 
        # Così "cuda" diventa "hip" MA "CUDA" diventa "HIP".
        $content = $content -creplace $pair.Old, $pair.New
    }

    # Scrivi solo se il file è effettivamente cambiato
    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -NoNewline
        Write-Host "Convertito contenuto: $($file.Name)" -ForegroundColor Green
    }
}

# Rinomina le cartelle fisiche se contengono CUDA (es. SHA256_CUDA -> SHA256_HIP)
Get-ChildItem -Directory -Recurse | Where-Object { $_.Name -match "CUDA" } | ForEach-Object {
    $newName = $_.Name -replace "CUDA", "HIP"
    # Controllo se esiste già per evitare errori
    if (-not (Test-Path (Join-Path $_.Parent.FullName $newName))) {
        Rename-Item $_.FullName -NewName $newName
        Write-Host "Rinominata cartella: $($_.Name) -> $newName" -ForegroundColor Yellow
    }
}

# correzione import ("..." -> <...>)
Get-ChildItem -Recurse -Include "*.cu", "*.cuh", "*.cpp", "*.h" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    # Sostituisce la versione con virgolette o senza cartella
    $newContent = $content -replace '#include "hip_runtime.h"', '#include <hip/hip_runtime.h>'
    $newContent = $newContent -replace '#include <hip_runtime.h>', '#include <hip/hip_runtime.h>'
    
    if ($content -ne $newContent) {
        Set-Content $_.FullName $newContent -NoNewline
        Write-Host "Corretto header in: $($_.Name)" -ForegroundColor Green
    }
}

# commento header inutili per HIP
Get-ChildItem -Recurse -Include "*.cu", "*.cuh", "*.cpp", "*.h" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    # Commenta l'include sia con virgolette che con parentesi
    $newContent = $content -replace '#include "device_launch_parameters.h"', '// #include "device_launch_parameters.h"'
    $newContent = $newContent -replace '#include <device_launch_parameters.h>', '// #include <device_launch_parameters.h>'
    
    if ($content -ne $newContent) {
        Set-Content $_.FullName $newContent -NoNewline
        Write-Host "Commentato header inutile in: $($_.Name)" -ForegroundColor Yellow
    }
}

# Rinomina file (Gestione Robusta Sovrascrittura)
Get-ChildItem -Recurse | Where-Object { $_.Name -match "cuda" } | ForEach-Object {
    $newName = $_.Name -replace "cuda", "hip"
    $targetPath = Join-Path $_.Directory.FullName $newName
    
    # Se il file di destinazione esiste già, lo eliminiamo per permettere la rinomina
    if (Test-Path $targetPath) {
        Remove-Item $targetPath -Force
        Write-Host "Sovrascritto esistente per rinomina: $newName" -ForegroundColor DarkCyan
    }

    Rename-Item $_.FullName -NewName $newName
    Write-Host "Rinominato file: $($_.Name) -> $newName" -ForegroundColor Cyan
}

# device property sintassi un po' diversa
Get-ChildItem -Recurse -Include "*.cu", "*.cpp", "*.h", "*.cuh" | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    
    # Corregge il nome della struct: hipDeviceProp -> hipDeviceProp_t
    $newContent = $content -replace '\bhipDeviceProp\b', 'hipDeviceProp_t'
    
    # Se manca l'include ma si usa hipDeviceProp, prova ad aggiungerlo (euristica semplice)
    if ($newContent -match "hipDeviceProp_t" -and $newContent -notmatch "hip/hip_runtime.h") {
        # Aggiunge l'include all'inizio del file
        $newContent = "#include <hip/hip_runtime.h>`n" + $newContent
        Write-Host "Aggiunto header mancante in: $($_.Name)" -ForegroundColor Yellow
    }

    if ($content -ne $newContent) {
        Set-Content $_.FullName $newContent -NoNewline
        Write-Host "Fixato hipDeviceProp in: $($_.Name)" -ForegroundColor Green
    }
}

Write-Host "Conversione completata." -ForegroundColor Green

Write-Host "ATTENZIONE: Prima di compilare assicurati che:" -ForegroundColor Red
Write-Host "1. Tutti i kernel siano lanciati con la sintassi con la tripla parentesi angolare senza spazi (esempio kernel <<<block, thread>>> (args))." -ForegroundColor Yellow
Write-Host "2. Le funzioni kernel siano __global__ ed extern C {} (sia in .cu che in .cuh)." -ForegroundColor Yellow
Write-Host "3. Controlla gli errori di compilazione." -ForegroundColor Yellow

$confirmation = Read-Host "Vuoi visualizzare i comandi suggeriti per la compilazione? (s/N)"

# Correzione logica: usa una regex per accettare s o S
if ($confirmation -notmatch "^[sS]$") { 
    exit 
}

$comandi = @'

=== COMANDI DI COMPILAZIONE SUGGERITI === (dalla stessa cartella dei kernel.cu)

# 1. NAIVE
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
    -DMAX_CANDIDATE=16 ` # definiamo esplicitamente un numero inferiore di MAX_CANDIDATE (rispetto a quello in UTILS/costanti.h)
    -o naive_amd.exe

# 2. V1 (Constant Memory)
hipcc -fgpu-rdc -O3 -std=c++14 --offload-arch=native `
     kernel_v1.cu `
     HIPv1/hip_v1.cu `
     SHA256_HIP/sha256.cu `
     UTILS/hip_utils.cu `
     UTILS/utils.cpp `
     -I. -I./HIPv1 -I./SHA256_HIP -I./UTILS `
     -I"D:\OpenSSL-Win64\include" `
     -L"D:\OpenSSL-Win64\lib\VC\x64\MTd" `
     -l libcrypto.lib `
     -D_CRT_SECURE_NO_WARNINGS `
     -DMAX_CANDIDATE=16 `
     -o v1_amd.exe

# 3. V2 (Optimized Kernel)
hipcc -fgpu-rdc -O3 -std=c++14 --offload-arch=native `
     kernel_v2.cu `
     HIPv2/hip_v2.cu `
     SHA256_HIP_OPT/sha256_opt.cu `
     UTILS/hip_utils.cu `
     UTILS/utils.cpp `
     -I. -I./HIPv2 -I./SHA256_HIP_OPT -I./UTILS `
     -I"D:\OpenSSL-Win64\include" `
     -L"D:\OpenSSL-Win64\lib\VC\x64\MTd" `
     -l libcrypto.lib `
     -D_CRT_SECURE_NO_WARNINGS `
     -DMAX_CANDIDATE=16 `
     -o v2_amd.exe

# 4. ESTENSIONE (Dizionario e Salt)
hipcc -fgpu-rdc -O3 -std=c++14 --offload-arch=native `
    kernel_estensione.cu `
    ESTENSIONE/DIZIONARIO/hip_dizionario.cu `
    ESTENSIONE/SALT/hip_salt.cu `
    SHA256_HIP/sha256.cu `
    UTILS/hip_utils.cu `
    UTILS/utils.cpp `
    -I. -I./ESTENSIONE/DIZIONARIO -I./ESTENSIONE/SALT -I./SHA256_HIP -I./UTILS `
    -I"D:\OpenSSL-Win64\include" `
    -L"D:\OpenSSL-Win64\lib\VC\x64\MTd" `
    -l libcrypto.lib `
    -D_CRT_SECURE_NO_WARNINGS `
    -o estensione_amd.exe
'@

Write-Host $comandi -ForegroundColor Gray