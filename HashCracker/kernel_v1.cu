#include <hip/hip_runtime.h>
// #include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <time.h>
#include "UTILS/hip_utils.cuh"
#include <math.h>
#include "HIP_NAIVE/hip_naive.cuh"
#include "UTILS/utils.h"
#include "HIPv1/hip_v1.cuh"

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

#define MAX_CANDIDATE 16
#define MAX_CHARSET_LENGTH 67

__constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
__constant__ char d_charSet[MAX_CHARSET_LENGTH];

int main(int argc, char** argv)
{
    /*invocazione: ./kernel [password_in_chiaro] [min_len] [max_len] [file_charset] [dizionario si/no] [file_dizionario] */

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    bool dizionario = false;
    double iStart, iElaps;
    int blockSize;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc < 6 && argc > 8) {
        printf("Usage: %s <block_size> <password_in_chiaro> <min_len> <max_len> <file_charset> <dizionario si/no> [file_dizionario]\n", argv[0]);
        return 1;
    }
    secret_password = argv[2];

    if (!safe_atoi(argv[1], &blockSize))
    {
        perror("Errore nella conversione di min_test_len");
        exit(1);
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

    if (argv[6][0] == 'S' || argv[6][0] == 's' || argv[6][0] == 'Y' || argv[6][0] == 'y')
    {
        dizionario = true;
    }

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
/* ---- TEST VERSIONE HIP v1 ---- */
/*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU v1 ---\n");
    // Allocazione variaibli device
    char* d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];

    CHECK(hipMemcpyToSymbol(d_target_hash, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)));

    CHECK(hipMemcpyToSymbol(d_charSet, charSet, charSetLen * sizeof(char)));

    CHECK(hipMalloc((void**)&d_found, sizeof(bool)));
    CHECK(hipMemset(d_found, false, sizeof(bool)));

    CHECK(hipMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(hipMemset(d_result, 0, max_test_len * sizeof(char)));

    iStart = cpuSecond();
    for (int len = min_test_len; len <= max_test_len; len++)
    {
        unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
        printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

        int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

        bruteForceKernel_v1 <<<numBlocks, blockSize>>> (
            len,
            d_result,
            charSetLen,
            totalCombinations,
            d_found
            );

        hipError_t err = hipGetLastError();
        if (err != hipSuccess)
            printf("ERRORE LANCIO KERNEL (len %d): %s\n", len, hipGetErrorString(err));
    }

    CHECK(hipDeviceSynchronize()); // Attendo terminazione kernel 
    CHECK(hipMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, hipMemcpyDeviceToHost));
    printf("Password decifrata: %s\n", h_result);

    iElaps = cpuSecond() - iStart;
    printf("Tempo GPU: %.4f secondi\n", iElaps);
    // Deallocazione variaibli device
    CHECK(hipFree(d_found));
    CHECK(hipFree(d_result));

    free(charSet);

    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    /* ---- TEST VERSIONE HIP v2 ---- */
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/

    return 0;
}
