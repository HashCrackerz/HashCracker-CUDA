#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include "../UTILS/hip_utils.cuh"
#include "../SHA256_HIP/sha256.cuh"
#include <stdio.h>

#define MAX_CANDIDATE 16
#define MAX_CHARSET_LENGTH 67 

extern __constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
extern __constant__ char d_charSet[MAX_CHARSET_LENGTH];

extern "C" {
    __global__ void bruteForceKernel_v1(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found)
    {
        unsigned long long idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
        unsigned long long stride = (unsigned long long)blockDim.x * gridDim.x;

        char candidate[MAX_CANDIDATE];

        while (idx < totalCombinations) {
            // Se qualcun altro ha trovato la password, smetto subito
            if (*d_found) break;

            // Genera la stringa usando d_charSet (che ora � visibile grazie a extern)
            idxToString(idx, candidate, len, d_charSet, charSetLen);

            // Calcola Hash 
            BYTE myHash[SHA256_DIGEST_LENGTH];
            dev_sha256((BYTE*)candidate, len, myHash);

            // Controlla risultato
            // ERRORE PRECEDENTE: avevi scritto 'target_hash', ma la variabile costante si chiama 'd_target_hash'
            if (check_hash_match(myHash, d_target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = true; // Usa true/false per i bool

                candidate[len] = '\0';

                // Copia il risultato per l'host
                for (int i = 0; i <= len; i++)
                {
                    d_result[i] = candidate[i];
                }
                break; // Break dal while
            }
            idx += stride;
        }
    }
}