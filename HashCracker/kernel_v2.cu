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
#include "CUDAv2/cuda_v2.cuh"

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

#define MAX_CANDIDATE 16
#define MAX_CHARSET_LENGTH 67

__constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
__constant__ char d_charSet[MAX_CHARSET_LENGTH];

int main(int argc, char** argv)
{
    /*invocazione: ./kernel [password_in_chiaro] [min_len] [max_len] [file_charset]  */

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    bool dizionario = false;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc != 5) {
        printf("Usage: %s <password_in_chiaro> <min_len> <max_len> <file_charset> \n", argv[0]);
        return 1;
    }
    secret_password = argv[1];

    if (!safe_atoi(argv[2], &min_test_len))
    {
        perror("Errore nella conversione di min_test_len");
        exit(1);
    }
    if (!safe_atoi(argv[3], &max_test_len))
    {
        perror("Errore nella conversione di max_test_len");
        exit(1);
    }

    charSet = leggiCharSet(argv[4]);
    int charSetLen = strlen(charSet);

    printf("%s Starting...\n", argv[0]);

    //Imposta il device CUDA
    int dev = 0;
    printDeviceProperties(dev);
    CHECK(cudaSetDevice(dev)); //Seleziona il device CUDA

    /* argomenti per invocare le funzioni di hash*/
    unsigned char target_hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);

    printf("\nTarget (segreto): '%s'\n", secret_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

    printf("min_test_len %d , max_test_len %d\n", min_test_len, max_test_len);
    printf("CharSet: %s\n", charSet);

    int blockSize = 256;

/*-----------------------------------------------------------------------------------------------------------------------------------------*/
/* ---- TEST VERSIONE CUDA v2 ---- */
/*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU v1 ---\n");
    // Allocazione variaibli device
    char* d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];

    CHECK(cudaMemcpyToSymbol(d_target_hash, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)));

    CHECK(cudaMemcpyToSymbol(d_charSet, charSet, charSetLen * sizeof(char)));

    CHECK(cudaMalloc((void**)&d_found, sizeof(bool)));
    CHECK(cudaMemset(d_found, false, sizeof(bool)));

    CHECK(cudaMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(cudaMemset(d_result, 0, max_test_len * sizeof(char)));


    for (int len = min_test_len; len <= max_test_len; len++)
    {
        unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
        printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

        int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

        bruteForceKernel_v2 << <numBlocks, blockSize >> > (
            len,
            d_result,
            charSetLen,
            totalCombinations,
            d_found
            );
    }

    CHECK(cudaDeviceSynchronize()); // Attendo terminazione kernel 
    CHECK(cudaMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, cudaMemcpyDeviceToHost));
    printf("Password decifrata: %s\n", h_result);

    // Deallocazione variaibli device
    CHECK(cudaFree(d_found));
    CHECK(cudaFree(d_result));


    free(charSet);
    return 0;
}
