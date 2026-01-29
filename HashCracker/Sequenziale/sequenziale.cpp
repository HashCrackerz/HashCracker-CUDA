#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h> 
#include <openssl/sha.h>
#include "sequenziale.h"

double cpuSecond() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return ((double)ts.tv_sec + (double)ts.tv_nsec * 1.e-9);
}

// Funzione helper per verificare l'hash
int check_hash(const char* password, int pass_len, unsigned char* target_hash) {
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, pass_len, current_hash);

    // memcmp restituisce 0 se i blocchi di memoria sono identici
    if (memcmp(current_hash, target_hash, SHA256_DIGEST_LENGTH) == 0) {
        return 1; // Trovato    
    }
    return 0; // Non trovato
}

void bruteForceSequenziale(int len, unsigned char target_hash[SHA256_DIGEST_LENGTH], char charSet[], char* result)
{
    int charSetLen = strlen(charSet);
    if (len <= 0) return;

    // Allocazione buffer per la stringa da creare e hashsare
    char* buf = (char*)malloc(sizeof(char) * (len + 1));
    if (buf == NULL) {
        fprintf(stderr, "Errore allocazione buf.\n");
        return;
    }
    buf[len] = '\0';

    // Allocazione array di INDICI
    /*
    * Viene mantenuto un array di dimensione pari a len in cui ogni elemento rappresenta
    * l'indice del corrispondente carattere del charSet che costituisce quell'elemento della stringa
    */
    int* indices = (int*)malloc(sizeof(int) * len);
    if (indices == NULL) {
        free(buf);
        fprintf(stderr, "Errore allocazione indices.\n");
        return;
    }

    // Inizializzazione indici a 0 -> stringa "aaaa..." [puntini non carattere ma ecc...]
    for (int i = 0; i < len; i++) {
        indices[i] = 0;
    }

    while (true) {
        // Costruzione stringa da testare in base agli indici
        for (int i = 0; i < len; i++) {
            buf[i] = charSet[indices[i]];
        }

        // Controllo se ho trovato l'hash corrispondente
        if (check_hash(buf, len, target_hash)) {
            strcpy(result, buf);
            break;
        }

        // Incrememento degli indici a partire dalla fine della stringa 
        /*
        * Si parte dell'ultimo carattere della stringa
        * Si provano tutte le combinazioni che si ottengono con i caratteri < i fissati e facendo variare
        * tutti i caratteri da "i" in poi [i � il carattere pi� a sinistra che cambia ( => != da "a" che � il default)]
        */
        int i = len - 1;
        while (i >= 0) {
            indices[i]++;
            if (indices[i] < charSetLen) {
                break;
            }
            else {
                indices[i] = 0;
                i--;// Cambio indice del carattere che modifico 
            }
        }

        if (i < 0) {
            break;
        }
    }

    free(indices);
    free(buf);
}

void testSequenziale(unsigned char* target_hash, int min_test_len, int max_test_len, char charSet[]) {
    printf("--- Inizio Test Brute Force CPU ---\n");

    char found_password[100] = { 0 };

    double iStart, iElaps;
    iStart = cpuSecond();

    for (int len = min_test_len; len <= max_test_len; len++) {
        printf("Tentativo lunghezza %d... ", len);
        fflush(stdout);

        bruteForceSequenziale(len, target_hash, charSet, found_password);

        if (strlen(found_password) > 0) {
            printf("TROVATA!\n");
            printf("Password decifrata: %s\n", found_password);
            break;
        }
        else {
            printf("Nessuna corrispondenza.\n");
        }
    }

    // end time 
    iElaps = cpuSecond() - iStart;
    printf("Tempo CPU: %.4f secondi\n", iElaps);

    if (strlen(found_password) == 0) {
        printf("\nPassword non trovata nel range di lunghezza 1-%d.\n", max_test_len);
    }
}