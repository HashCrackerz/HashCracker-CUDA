#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h >
#include "Sequenziale/sequenziale.h"
#include <time.h>

char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri


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

void testSequenziale(char *secret_password, int min_test_len, int max_test_len) {    
    unsigned char target_hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);

    printf("--- Inizio Test Brute Force CPU ---\n");
    printf("Target (segreto): '%s'\n", secret_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

    char found_password[100] = { 0 };

    // start time 
    clock_t start = clock(); //clock() restituisce il numero di tick dall'avvio del programma

    for (int len = min_test_len; len <= max_test_len; len++) {
        printf("Tentativo lunghezza %d... ", len);
        fflush(stdout);

        bruteForceSequenziale(len, target_hash, charset, found_password);

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
    clock_t end = clock();
    double seconds = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Tempo CPU: %.4f secondi\n", seconds);

    printf("Tempo impiegato: %ld", (end - start));

    if (strlen(found_password) == 0) {
        printf("\nPassword non trovata nel range di lunghezza 1-%d.\n", max_test_len);
    }
}

int main(int argc, char** argv)
{
    /*
    if (argc != 2) {
        printf("Usage: %s <image_file>\n", argv[0]);
        return 1;
    }
    printf("%s Starting...\n", argv[0]);*/

    char* secret_password = "abcd3";
    int max_test_len = 5;
    int min_test_len = 1; 

    /* TEST VERSIONE SEQUENZIALE */
    testSequenziale(secret_password, min_test_len, max_test_len);

    //Imposta il device CUDA
    int dev = 0;
    cudaDeviceProp deviceProp;
    CHECK(cudaGetDeviceProperties(&deviceProp, dev)); //Ottiene le proprietà del device 
    printf("Using Device %d: %s\n", dev, deviceProp.name);
    CHECK(cudaSetDevice(dev)); //Seleziona il device CUDA

    return 0;
}
