#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "UTILS/hip_utils.cuh"
#include <math.h>
#include "HIP_NAIVE/hip_naive.cuh"
#include "UTILS/utils.h"
#include <openssl/sha.h>

#define CHECK(call) \
{ \
    const hipError_t error = call; \
    if (error != hipSuccess) \
    { \
        printf("Error: %s:%d, ", __FILE__, __LINE__); \
        printf("code: %d, reason: %s\n", error, hipGetErrorString(error)); \
        exit(1); \
    } \
}

int main(int argc, char** argv)
{
    /*invocazione: ./kernel <block_size> <password_in_chiaro> <min_len> <max_len> <file_charset>  */

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    int blockSize;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc != 6) {
        printf("Usage: %s <password_in_chiaro> <min_len> <max_len> <file_charset> \n", argv[0]);
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


    printf("%s Starting...\n", argv[0]);

    //Imposta il device HIP
    int dev = 0;
    printDeviceProperties(dev);
    CHECK(hipSetDevice(dev)); //Seleziona il device HIP

    /* argomenti per invocare le funzioni di hash*/
    unsigned char target_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);

    printf("\nTarget (segreto): '%s'\n", secret_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

    printf("min_test_len %d , max_test_len %d\n", min_test_len, max_test_len);
    printf("CharSet: %s\n", charSet);

    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    /* TEST VERSIONE HIP NAIVE */
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU NAIVE ---\n");
    // Allocazione variaibli device
    BYTE* d_target_hash;
    char* d_charSet, * d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];

    double iStart, iElaps;
    iStart = cpuSecond();

    CHECK(hipMalloc((void**)&d_target_hash, sizeof(BYTE) * SHA256_DIGEST_LENGTH));
    CHECK(hipMemcpy(d_target_hash, target_hash, sizeof(BYTE) * SHA256_DIGEST_LENGTH, hipMemcpyHostToDevice));

    CHECK(hipMalloc((void**)&d_charSet, sizeof(char) * charSetLen));
    CHECK(hipMemcpy(d_charSet, charSet, sizeof(char) * charSetLen, hipMemcpyHostToDevice));

    CHECK(hipMalloc((void**)&d_found, sizeof(bool)));
    CHECK(hipMemset(d_found, false, sizeof(bool)));

    CHECK(hipMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(hipMemset(d_result, 0, max_test_len * sizeof(char)));


    for (int len = min_test_len; len <= max_test_len; len++)
    {
        unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
        printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

        int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

        bruteForceKernel_Naive <<<numBlocks, blockSize>>> (
            len,
            d_target_hash,
            d_charSet,
            d_result,
            charSetLen,
            totalCombinations,
            d_found
            );
    }

    CHECK(hipDeviceSynchronize()); // Attendo terminazione kernel
    CHECK(hipMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, hipMemcpyDeviceToHost));
    printf("Password decifrata: %s\n", h_result);

    // end time 
    iElaps = cpuSecond() - iStart;
    printf("Tempo GPU: %.4f secondi\n", iElaps);

    // Deallocazione variaibli device
    CHECK(hipFree(d_charSet));
    CHECK(hipFree(d_target_hash));
    CHECK(hipFree(d_found));
    CHECK(hipFree(d_result));

    free(charSet);

    return 0;
}
