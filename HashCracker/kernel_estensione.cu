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
#include "ESTENSIONE/DIZIONARIO/cuda_dizionario.cuh"

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

//memoria const
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
        perror("Errore nella conversione di blockSize");
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
    char* dict_path = (argc == 9) ? argv[8] : "ASSETS/rockyou.txt";

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
    bool password_found = false;

    CHECK(cudaMemcpyToSymbol(d_target_hash, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)));
    CHECK(cudaMemcpyToSymbol(d_charSet, charSet, charSetLen * sizeof(char)));
    CHECK(cudaMemcpyToSymbol(d_salt, salt, MAX_SALT_LENGTH * sizeof(char)));


    CHECK(cudaMalloc((void**)&d_found, sizeof(bool)));
    CHECK(cudaMemset(d_found, false, sizeof(bool)));

    CHECK(cudaMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(cudaMemset(d_result, 0, max_test_len * sizeof(char)));


    if (dizionario)
    {
        //provo con attacco a dizionario: se la parola è tra quelle del dizionario la trovo 
        //immediatamente, altrimenti provo con l'attacco classico
        printf("---  Attacco a Dizionario CUDA ---\n");
        printf("Lettura e linearizzazione file '%s'...\n", dict_path);

        int numWords = 0;

        char* h_flatDict = load_flattened_dictionary(dict_path, &numWords);

        if (h_flatDict != NULL && numWords > 0)
        {
            char* d_dictionary = NULL;
            // Calcolo dimensione totale buffer: numero parole * lunghezza fissa (padding incluso)
            size_t dictSizeBytes = (size_t)numWords * DICT_WORD_LEN * sizeof(char);

            // Allocazione Device
            CHECK(cudaMalloc((void**)&d_dictionary, dictSizeBytes));
            // Copia su GPU
            CHECK(cudaMemcpy(d_dictionary, h_flatDict, dictSizeBytes, cudaMemcpyHostToDevice));


            unsigned long long totalSalts = pow((double)charSetLen, (double)strlen(salt));
            int numBlocks = (numWords + blockSize - 1) / blockSize;

            printf("Lancio Kernel Dizionario su %d parole (%.2f MB)...\n", numWords, dictSizeBytes / (1024.0 * 1024.0));

            bruteForceKernel_dizionario << <numBlocks, blockSize >> > (
                d_dictionary, numWords, strlen(salt),
                charSetLen, totalSalts, d_result, d_found
                );
            CHECK(cudaDeviceSynchronize());

            // Check Risultato
            bool h_found = false;
            CHECK(cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost));

            if (h_found) {

                CHECK(cudaMemcpy(h_result, d_result, MAX_CANDIDATE * sizeof(char), cudaMemcpyDeviceToHost));

                printf("\nParola candidata trovata dalla GPU: %s\n", h_result);

                if (testLogin(h_result, strlen(h_result), target_hash, salt)) {
                    printf("\n************************************************\n");
                    printf("*** PASSWORD TROVATA E VERIFICATA: %s ***\n", h_result);
                    printf("************************************************\n");
                    password_found = true;
                }
            }
            else {
                printf("Non trovata nel dizionario.\n");
            }

            // Cleanup 
            free(h_flatDict);
            CHECK(cudaFree(d_dictionary));
        }
        else {
            printf("Impossibile caricare il dizionario o dizionario vuoto.\n");
        }
    }

    // Se non trovata nel dizionario, o se dizionario disattivato, procedo col Brute Force
    if (!password_found)
    {
        if (dizionario) printf("\n--- Password non trovata con attacco a dizionario, provo con brute force classico (con salt)  ---\n");

        CHECK(cudaMemset(d_found, false, sizeof(bool)));

        //NOTA: le test_len includono anche la lunghezza del salt
        for (int len = min_test_len; len <= max_test_len; len++)
        {
            if (password_found) break;

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

            CHECK(cudaDeviceSynchronize());

            bool h_found_local = false;
            CHECK(cudaMemcpy(&h_found_local, d_found, sizeof(bool), cudaMemcpyDeviceToHost));

            if (h_found_local) {
                password_found = true;

                CHECK(cudaMemcpy(h_result, d_result, MAX_CANDIDATE * sizeof(char), cudaMemcpyDeviceToHost));
                printf("\n************************************************\n");
                printf("*** PASSWORD TROVATA (Brute Force): %s ***\n", h_result);
                printf("************************************************\n");

                break; 
            }
        }
    }

    CHECK(cudaDeviceSynchronize()); // Attendo terminazione kernel 

    if (!password_found) {
        printf("\nNessuna password trovata nel range specificato.\n");
    }

    // Cleanup
    CHECK(cudaFree(d_found));
    CHECK(cudaFree(d_result));

    free(charSet);
    free(salted_password);

    return 0;
}
