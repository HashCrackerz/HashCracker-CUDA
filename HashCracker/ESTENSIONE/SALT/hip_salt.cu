#include "hip_salt.cuh"

extern "C" {
    __global__ void bruteForceKernel_salt(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found)
    {
        unsigned long long idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
        unsigned long long stride = (unsigned long long)blockDim.x * gridDim.x;

        char candidate[MAX_CANDIDATE + MAX_SALT_LENGTH];

        while (idx < totalCombinations) {
            if (*d_found) break;

            idxToString(idx, candidate, len, d_charSet, charSetLen);

            BYTE myHash[SHA256_DIGEST_LENGTH];
            dev_sha256((BYTE*)candidate, len, myHash);

            if (check_hash_match(myHash, d_target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = true;

                candidate[len] = '\0';

                for (int i = 0; i <= len; i++)
                {
                    d_result[i] = candidate[i];
                }
                break;
            }

            idx += stride;
        }
    }
}