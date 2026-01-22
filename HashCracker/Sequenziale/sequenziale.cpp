#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <openssl/sha.h>

// Charset globale
char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri


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

void bruteForce(int len, unsigned char target_hash[SHA256_DIGEST_LENGTH], char charSet[], char* result)
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
        * tutti i caratteri da "i" in poi [i è il carattere più a sinistra che cambia ( => != da "a" che è il default)]
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

// --- MAIN DI PROVA ---

int main() {

    const char* secret_password = "abcd3";
    unsigned char target_hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);

    printf("--- Inizio Test Brute Force CPU ---\n");
    printf("Target (segreto): '%s'\n", secret_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

    char found_password[100] = { 0 }; 


    int max_test_len = 5;

    for (int len = 1; len <= max_test_len; len++) {
        printf("Tentativo lunghezza %d... ", len);
        fflush(stdout); 

        bruteForce(len, target_hash, charset, found_password);

        if (strlen(found_password) > 0) {
            printf("TROVATA!\n");
            printf("Password decifrata: %s\n", found_password);
            break; 
        }
        else {
            printf("Nessuna corrispondenza.\n");
        }
    }

    if (strlen(found_password) == 0) {
        printf("\nPassword non trovata nel range di lunghezza 1-%d.\n", max_test_len);
    }

    return 0;
}