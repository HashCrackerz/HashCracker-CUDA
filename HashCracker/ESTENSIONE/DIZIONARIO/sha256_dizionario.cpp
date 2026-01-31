#include "sha256_dizionario.h"

// Funzione helper locale
void remove_newline(char* str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

char* testSequenziale_dizionario(BYTE* target_hash, int saltLen, char* charSet, char* found_salt) {
    int numWords = 0;
    // Carichiamo il dizionario in RAM (Stride costante definito da DICT_WORD_LEN)
    char* flatDict = load_flattened_dictionary("rockyou_trimmed.txt", &numWords);

    if (!flatDict) return NULL;

    int charSetLen = strlen(charSet);
    char* result_password = NULL;
    bool found = false;

    // Buffer temporaneo per il salt corrente
    char* current_salt = (char*)malloc(saltLen + 1);
    if (!current_salt) { free(flatDict); return NULL; }
    current_salt[saltLen] = '\0';

    // Buffer per la concatenazione salt + parola
    char salted_combined[DICT_WORD_LEN + 64];

    printf("Dizionario caricato: %d parole. Avvio scansione...\n", numWords);

    for (int w = 0; w < numWords && !found; w++) {
        char* word = &flatDict[w * DICT_WORD_LEN];
        int wordLen = strlen(word);

        int* indices = (int*)calloc(saltLen, sizeof(int));
        if (!indices) break;

        while (true) {
            for (int i = 0; i < saltLen; i++) {
                current_salt[i] = charSet[indices[i]];
            }

            // Costruiamo la stringa: SALT + PAROLA
            memcpy(salted_combined, current_salt, saltLen);
            memcpy(salted_combined + saltLen, word, wordLen);
            int combinedLen = saltLen + wordLen;

            BYTE current_hash[SHA256_DIGEST_LENGTH];
            SHA256((unsigned char*)salted_combined, combinedLen, current_hash);

            if (memcmp(current_hash, target_hash, SHA256_DIGEST_LENGTH) == 0) {
                found = true;
                strcpy(found_salt, current_salt);

                result_password = (char*)malloc((wordLen + 1) * sizeof(char));
                if (result_password != NULL) {
                    strcpy(result_password, word);
                }
                break;
            }

            int i = saltLen - 1;
            while (i >= 0) {
                indices[i]++;
                if (indices[i] < charSetLen) break;
                indices[i] = 0;
                i--;
            }
            if (i < 0) break;
        }
        free(indices);
    }

    free(current_salt);
    free(flatDict);
    return result_password;
}
