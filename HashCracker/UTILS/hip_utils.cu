#include <hip/hip_runtime.h>
#include "hip_utils.cuh"


__device__ void idxToString(unsigned long long idx, char* result, int len, char* charset, int charsetLen) {
    // Si riempie la stringa partendo dall'ultimo carattere (destra verso sinistra)
    for (int i = len - 1; i >= 0; i--) {
        // Il resto della divisione indica il carattere (rispetto al charset) 
        int charIndex = idx % charsetLen;

        result[i] = charset[charIndex];

        // Si passa alla posizione successiva (a sinistra)
        idx /= charsetLen;
    }
}

__device__ bool check_hash_match(const unsigned char* hash1, const unsigned char* hash2, int hashLen) {
    // Unroll del loop per massimizzare le prestazioni (opzionale, ma aiuta)
#pragma unroll
    for (int i = 0; i < hashLen; i++) {
        if (hash1[i] != hash2[i]) {
            return false; // Appena trovo un byte diverso, esco
        }
    }
    return true;
}

float bytesToGB(size_t bytes) {
    return (float)bytes / (1024.0f * 1024.0f * 1024.0f);
}


// Funzione per stampare le propriet� di un dispositivo
void printDeviceProperties(int deviceId) {
    hipDeviceProp_t prop;
    hipGetDeviceProperties(&prop, deviceId);

    printf("\n=================================================\n");
    printf("Dispositivo %d: %s", deviceId, prop.name);
    printf("\n=================================================\n");

    // 1. Compute Capability
    printf("1. Compute Capability: %d.%d\n", prop.major, prop.minor);

    // 2. Memoria Globale Totale
    printf("2. Memoria Globale Totale: %.2f GB\n", bytesToGB(prop.totalGlobalMem));

    // 3. Numero di Multiprocessori
    printf("3. Numero di Multiprocessori: %d\n", prop.multiProcessorCount);

    // 4. Clock Core
    //printf("4. Clock Core: %d MHz\n", prop.clockRate / 1000);

    // 5. Clock Memoria
    //printf("5. Clock Memoria: %d MHz\n", prop.memoryClockRate / 1000);

    // 6. Larghezza Bus Memoria
    printf("6. Larghezza Bus Memoria: %d bit\n", prop.memoryBusWidth);

    // 7. Dimensione Cache L2
    printf("7. Dimensione Cache L2: %d KB\n", prop.l2CacheSize / 1024);

    // 8. Memoria Condivisa per Blocco
    printf("8. Memoria Condivisa per Blocco: %zu KB\n", prop.sharedMemPerBlock / 1024);

    // 9. Numero Massimo di Thread per Blocco
    printf("9. Numero Massimo di Thread per Blocco: %d\n", prop.maxThreadsPerBlock);

    // 10. Dimensioni Massime Griglia
    printf("10. Dimensioni Massime Griglia: (%d, %d, %d)\n",
        prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);

    // 11. Dimensioni Massime Blocco
    printf("11. Dimensioni Massime Blocco: (%d, %d, %d)\n",
        prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2]);

    // 12. Warp Size
    printf("12. Warp Size: %d\n", prop.warpSize);

    // 13. Memoria Costante Totale
    printf("13. Memoria Costante Totale: %zu bytes\n", prop.totalConstMem);

    // 14. Texture Alignment
    printf("14. Texture Alignment: %zu bytes\n", prop.textureAlignment);

    printf("\n");
}