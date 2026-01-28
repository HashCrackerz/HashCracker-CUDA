#include "sha256_dizionario.h"

// Funzione helper locale
void remove_newline(char* str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

char* testSequenziale_dizionario(BYTE* target_hash, int saltLen, char* charSet, char* found_salt)
{
    //apro il file dizionario
    FILE* file = fopen("ASSETS/rockyou.txt", "r");
    if (!file) {
        perror("Errore apertura file rockyou.txt");
        return NULL;
    }

    int charSetLen = strlen(charSet);

    
    int* indices = (int*)calloc(saltLen, sizeof(int));
    if (!indices) { fclose(file); return NULL; }

    char* current_salt = (char*)malloc(saltLen + 1);
    if (!current_salt) { free(indices); fclose(file); return NULL; }
    current_salt[saltLen] = '\0';

    char line_buf[256];      // Buffer per leggere la password dal file
    char* result_password = NULL;
    bool found = false;

    // Generazione di tutti i possibili SALT ---
    while (true) {
        // Costruzione della stringa salt corrente in base agli indici
        for (int i = 0; i < saltLen; i++) {
            current_salt[i] = charSet[indices[i]];
        }

        // --- Scansione del dizionario ---
        rewind(file); // Si riparte dall'inizio del file per ogni nuovo salt

        while (fgets(line_buf, sizeof(line_buf), file)) {
            remove_newline(line_buf);
            int passLen = strlen(line_buf);

            if (testLogin(line_buf, passLen, target_hash, current_salt) == 1) {
                found = true;

                strcpy(found_salt, current_salt);

                result_password = (char*)malloc((passLen + 1) * sizeof(char));
                if (result_password != NULL) {
                    strcpy(result_password, line_buf);
                }
                break;
            }
        }

        if (found) break;

        int i = saltLen - 1;
        while (i >= 0) {
            indices[i]++;
            if (indices[i] < charSetLen) {
                break;
            }
            else {
                indices[i] = 0;
                i--;
            }
        }

        if (i < 0) break;
    }

    // Pulizia memoria
    free(indices);
    free(current_salt);
    fclose(file);

    return result_password; // Ritorna la password o NULL
}