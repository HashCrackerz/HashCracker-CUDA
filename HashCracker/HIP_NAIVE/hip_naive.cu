#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include "../UTILS/hip_utils.cuh"
#include "../SHA256_HIP/sha256.cuh"
#include <stdio.h>

/* dato che 67 ^ 16 è un numero enorme non è tempisticamente possibile provare con numeri maggiori*/
#define MAX_CANDIDATE 16

__global__ void bruteForceKernel_Naive(int len, BYTE target_hash[], char *d_charSet, char *d_result, 
    int charSetLen, unsigned long long totalCombinations, bool *d_found)
{
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned long long stride = blockDim.x * gridDim.x;

    char candidate[MAX_CANDIDATE]; 

    while (idx < totalCombinations) {
        // Se qualcun altro ha trovato la password, smetto subito
        if (*d_found) break;

        // Genera la stringa
        idxToString(idx, candidate, len, d_charSet, charSetLen);

        // Calcola Hash 
        BYTE myHash[SHA256_DIGEST_LENGTH];
        dev_sha256((BYTE*)candidate, len, myHash);

        // Controlla risultato
        if (check_hash_match(myHash, target_hash, SHA256_DIGEST_LENGTH)) {
            *d_found = 1;

            candidate[len] = '\0';

            // Copia il risultato per l'host
            for (int i = 0; i <= len; i++) 
            {
                d_result[i] = candidate[i];
            }

            break;
        }

        idx += stride; 
    }
}