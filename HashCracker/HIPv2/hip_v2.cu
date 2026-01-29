#include "hip_v2.cuh"

extern "C" {
    __global__ void bruteForceKernel_v2(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found)
    {
        unsigned long long idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
        unsigned long long stride = (unsigned long long)blockDim.x * gridDim.x;

        char candidate[MAX_CANDIDATE];

        while (idx < totalCombinations) {
            // Se qualcun altro ha trovato la password, smetto subito
            if (*d_found) break;

            // Genero la stringa usando d_charSet
            idxToString(idx, candidate, len, d_charSet, charSetLen);

            // Calcola Hash 
            BYTE myHash[SHA256_DIGEST_LENGTH];
            dev_sha256((BYTE*)candidate, len, myHash);

            // Controllo risultato
            if (check_hash_match(myHash, d_target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = true; 

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