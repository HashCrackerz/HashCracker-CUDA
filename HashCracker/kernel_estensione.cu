#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "Sequenziale/sequenziale.h"
#include <time.h>
#include "UTILS/cuda_utils.cuh"
#include <math.h>
#include "CUDA_NAIVE/cuda_naive.cuh"
#include "UTILS/utils.h"
#include "ESTENSIONE/SALT/cuda_salt.cuh"
#include "UTILS/costanti.h"

#define CHECK(call) \
{ \
    const cudaError_t error = call; \
    if (error != cudaSuccess) \
    { \
        printf("Error: %s:%d, ", __FILE__, __LINE__); \
        printf("code: %d, reason: %s\n", error, cudaGetErrorString(error)); \
        exit(1); \
    } \
}

__constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
__constant__ char d_charSet[MAX_CHARSET_LENGTH];
__constant__ char d_salt[MAX_SALT_LENGTH];

int main(int argc, char** argv)
{
    /*invocazione: ./kernel <block_size> <password_in_chiaro> <min_len> <max_len> <file_charset> <dizionario si/no> [file_dizionario]*/

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    int blockSize;
    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    bool dizionario = false;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc != 8 && argc != 9) {
        printf("Usage: %s <block_size> <password_in_chiaro> <min_len> <max_len> <file_charset> <salt> <dizionario si/no> [file_dizionario]\n", argv[0]);
        return 1;
    }
    secret_password = argv[2];

    if (!safe_atoi(argv[1], &blockSize))
    {
        perror("Errore nella conversione di min_test_len");
        exit(1);
        if (blockSize % 32 != 0)
        {
            perror("Warning... block_size dovrebbe essere multiplo di 32");
        }
    }

    if (!safe_atoi(argv[3], &min_test_len))
    {
        perror("Errore nella conversione di min_test_len");
        exit(1);
    }
    if (!safe_atoi(argv[4], &max_test_len))
    {
        perror("Errore nella conversione di max_test_len");
        exit(1);
    }

    charSet = leggiCharSet(argv[5]);
    int charSetLen = strlen(charSet);

    char* salt = argv[6];

    if (argv[7][0] == 'S' || argv[7][0] == 's' || argv[7][0] == 'Y' || argv[7][0] == 'y')
    {
        dizionario = true;
    }

    //Imposta il device CUDA
    int dev = 0;
    printDeviceProperties(dev);
    CHECK(cudaSetDevice(dev)); //Seleziona il device CUDA

    printf("%s Starting...\n", argv[0]);

    BYTE target_hash[SHA256_DIGEST_LENGTH];
    char* salted_password = salt_password(secret_password, strlen(secret_password), salt, strlen(salt));
    SHA256((const unsigned char*)salted_password, strlen(salted_password), target_hash);

    printf("Salted password da trovare: %s\n", salted_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

/*-----------------------------------------------------------------------------------------------------------------------------------------*/
/* ---- TEST ESTENSIONE CUDA (basato su CUDAv2) ---- */
/*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU [estensione] ---\n");
    // Allocazione variaibli device
    char* d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];

    CHECK(cudaMemcpyToSymbol(d_target_hash, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)));
    CHECK(cudaMemcpyToSymbol(d_charSet, charSet, charSetLen * sizeof(char)));
    CHECK(cudaMemcpyToSymbol(d_salt, salt, MAX_SALT_LENGTH * sizeof(char)));


    CHECK(cudaMalloc((void**)&d_found, sizeof(bool)));
    CHECK(cudaMemset(d_found, false, sizeof(bool)));

    CHECK(cudaMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(cudaMemset(d_result, 0, max_test_len * sizeof(char)));

    //NOTA: le test_len includono anche la lunghezza del salt
    for (int len = min_test_len; len <= max_test_len; len++)
    {
        unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
        printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

        int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

        bruteForceKernel_salt << <numBlocks, blockSize >> > (
            len,
            d_result,
            charSetLen,
            totalCombinations,
            d_found
            );
    }

    CHECK(cudaDeviceSynchronize()); // Attendo terminazione kernel 
    CHECK(cudaMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, cudaMemcpyDeviceToHost));
    printf("Password + salt decifrati: %s\n", h_result);
    if (strlen(h_result) > 0)
    {
        printf("Stringa Totale (Pass+Salt) trovata: %s\n", h_result);

        char* final_decrypted_pass = NULL;
        int totalLen = strlen(h_result);
        int mySaltLen = strlen(salt);
        int realPassLen = totalLen - mySaltLen;

        if (realPassLen > 0)
        {
            // Controllo se il salt è all'INIZIO
            // (Confronto i primi N caratteri di h_result con il salt)
            if (strncmp(h_result, salt, mySaltLen) == 0)
            {
                // La password è tutto ciò che viene dopo il salt
                final_decrypted_pass = (char*)malloc(sizeof(char) * (realPassLen + 1));
                strcpy(final_decrypted_pass, h_result + mySaltLen);
                printf("Schema rilevato: [SALT] + [PASSWORD]\n");
            }
            // Controllo se il salt è alla FINE
            // (Confronto la parte finale di h_result con il salt)
            else if (strncmp(h_result + realPassLen, salt, mySaltLen) == 0)
            {
                // La password è la prima parte della stringa
                final_decrypted_pass = (char*)malloc(sizeof(char) * (realPassLen + 1));
                strncpy(final_decrypted_pass, h_result, realPassLen);
                final_decrypted_pass[realPassLen] = '\0'; // Terminatore manuale
                printf("Schema rilevato: [PASSWORD] + [SALT]\n");
            }
        }

        if (final_decrypted_pass != NULL) {
            printf("\n*** PASSWORD TROVATA: %s ***\n", final_decrypted_pass);
            free(final_decrypted_pass);
        }
        else {
            printf("Errore: Hash trovato, ma il salt non corrisponde alla posizione prevista.\n");
        }
    }
    else {
        printf("Nessuna password trovata nel range specificato.\n");
    }

    // Deallocazione variabili 
    CHECK(cudaFree(d_found));
    CHECK(cudaFree(d_result));

    free(charSet);
    return 0;
}
