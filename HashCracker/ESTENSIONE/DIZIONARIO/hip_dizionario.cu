#include "hip_dizionario.cuh"

extern "C" {
    __global__ void bruteForceKernel_dizionario(char* d_dictionary, int numWords, int saltLen,
        int charSetLen, unsigned long long totalSalts, char* d_result, bool* d_found)
    {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;

        if (idx >= numWords) return;
        if (*d_found) return;

        char myWord[DICT_WORD_LEN];
        // Calcolo indirizzo parola i-esima (accesso allineato)
        char* wordPtr = &d_dictionary[idx * DICT_WORD_LEN];

        int wordLen = 0;
        for (int i = 0; i < DICT_WORD_LEN; i++) {
            char c = wordPtr[i];
            myWord[i] = c;
            if (c == '\0' && wordLen == 0) wordLen = i;
        }
        if (wordLen == 0) return; // Parola vuota o non valida

        //Brute Force Salt
        char salt[MAX_SALT_LENGTH];
        char combined[DICT_WORD_LEN + MAX_SALT_LENGTH];
        BYTE myHash[SHA256_DIGEST_LENGTH];

        for (unsigned long long sIdx = 0; sIdx < totalSalts; sIdx++)
        {
            if (*d_found) break;

            //Genera salt
            idxToString(sIdx, salt, saltLen, d_charSet, charSetLen);

            // Prima salt e poi password
            int k = 0;
            for (int i = 0; i < saltLen; i++) combined[k++] = salt[i];
            for (int i = 0; i < wordLen; i++) combined[k++] = myWord[i];

            dev_sha256((BYTE*)combined, k, myHash);

            if (check_hash_match(myHash, d_target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = true;
                combined[k] = '\0';
                for (int i = 0; i <= k; i++) d_result[i] = combined[i];
                return;
            }

            // Prima password e poi salt
            k = 0;
            for (int i = 0; i < wordLen; i++) combined[k++] = myWord[i];
            for (int i = 0; i < saltLen; i++) combined[k++] = salt[i];

            dev_sha256((BYTE*)combined, k, myHash);

            if (check_hash_match(myHash, d_target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = true;
                combined[k] = '\0';
                for (int i = 0; i <= k; i++) d_result[i] = combined[i];
                return;
            }
        }
    }
}