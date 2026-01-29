#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "Sequenziale/sequenziale.h"
#include <time.h>
#include "UTILS/hip_utils.cuh"
#include <math.h>
#include "HIP_NAIVE/hip_naive.cuh"
#include "UTILS/utils.h"
#include "ESTENSIONE/SALT/hip_salt.cuh"
#include "UTILS/costanti.h"
#include "ESTENSIONE/DIZIONARIO/hip_dizionario.cuh"

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

//memoria const
__constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
__constant__ char d_charSet[MAX_CHARSET_LENGTH];
__constant__ char d_salt[MAX_SALT_LENGTH];

int main(int argc, char** argv)
{
    //invocazione: ./kernel <block_size> <password_in_chiaro> <min_len> <max_len> <file_charset> <salt> <dizionario si/no> [file_dizionario]

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
    const char* dict_path = (argc == 9) ? argv[8] : "ASSETS/rockyou.txt";

    //Imposta il device HIP
    int dev = 0;
    printDeviceProperties(dev);
    CHECK(hipSetDevice(dev)); //Seleziona il device HIP

    printf("%s Starting...\n", argv[0]);

    BYTE target_hash[SHA256_DIGEST_LENGTH];
    char* salted_password = salt_password(secret_password, strlen(secret_password), salt, strlen(salt));
    SHA256((const unsigned char*)salted_password, strlen(salted_password), target_hash);

    printf("Salted password da trovare: %s\n", salted_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

/*-----------------------------------------------------------------------------------------------------------------------------------------*/
/* ---- TEST ESTENSIONE HIP (basato su HIPv2) ---- */
/*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU [estensione] ---\n");
    // Allocazione variaibli device
    char* d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];
    bool password_found = false;

    CHECK(hipMemcpyToSymbol(d_target_hash, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)));
    CHECK(hipMemcpyToSymbol(d_charSet, charSet, charSetLen * sizeof(char)));
    CHECK(hipMemcpyToSymbol(d_salt, salt, MAX_SALT_LENGTH * sizeof(char)));


    CHECK(hipMalloc((void**)&d_found, sizeof(bool)));
    CHECK(hipMemset(d_found, false, sizeof(bool)));

    CHECK(hipMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(hipMemset(d_result, 0, max_test_len * sizeof(char)));

    double iStart, iElaps;
    iStart = cpuSecond();

    if (dizionario)
    {
        //provo con attacco a dizionario: se la parola � tra quelle del dizionario la trovo 
        //immediatamente, altrimenti provo con l'attacco classico
        printf("---  Attacco a Dizionario HIP ---\n");
        printf("Lettura e linearizzazione file '%s'...\n", dict_path);

        int numWords = 0;

        char* h_flatDict = load_flattened_dictionary(dict_path, &numWords);

        if (h_flatDict != NULL && numWords > 0)
        {
            char* d_dictionary = NULL;
            // Calcolo dimensione totale buffer: numero parole * lunghezza fissa (padding incluso)
            size_t dictSizeBytes = (size_t)numWords * DICT_WORD_LEN * sizeof(char);

            // Allocazione Device
            CHECK(hipMalloc((void**)&d_dictionary, dictSizeBytes));
            // Copia su GPU
            CHECK(hipMemcpy(d_dictionary, h_flatDict, dictSizeBytes, hipMemcpyHostToDevice));


            unsigned long long totalSalts = pow((double)charSetLen, (double)strlen(salt));
            int numBlocks = (numWords + blockSize - 1) / blockSize;

            printf("Lancio Kernel Dizionario su %d parole (%.2f MB)...\n", numWords, dictSizeBytes / (1024.0 * 1024.0));

            bruteForceKernel_dizionario <<<numBlocks, blockSize>>> (
                d_dictionary, numWords, strlen(salt),
                charSetLen, totalSalts, d_result, d_found
                );
            CHECK(hipDeviceSynchronize());

            // Check Risultato
            bool h_found = false;
            CHECK(hipMemcpy(&h_found, d_found, sizeof(bool), hipMemcpyDeviceToHost));

            if (h_found) {
                CHECK(hipMemcpy(h_result, d_result, MAX_CANDIDATE * sizeof(char), hipMemcpyDeviceToHost));
                printf("\n*** PASSWORD TROVATA (Dizionario): %s ***\n", h_result);
                password_found = true;
            }
            else {
                printf("Non trovata nel dizionario.\n");
            }

            // Cleanup 
            free(h_flatDict);
            CHECK(hipFree(d_dictionary));
        }
        else {
            printf("Impossibile caricare il dizionario o dizionario vuoto.\n");
        }
    }

    // Se non trovata nel dizionario, o se dizionario disattivato, procedo col Brute Force
    if (!password_found)
    {
        if (dizionario) printf("\n--- Password non trovata con attacco a dizionario, provo con brute force classico (con salt)  ---\n");

        CHECK(hipMemset(d_found, false, sizeof(bool)));

        //NOTA: le test_len includono anche la lunghezza del salt
        for (int len = min_test_len; len <= max_test_len; len++)
        {
            if (password_found) break;

            unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
            printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

            int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

            bruteForceKernel_salt <<<numBlocks, blockSize>>> (
                len,
                d_result,
                charSetLen,
                totalCombinations,
                d_found
                );

            CHECK(hipDeviceSynchronize());

            // Check immediato per uscire dal ciclo for
            bool h_found_local = false;
            CHECK(hipMemcpy(&h_found_local, d_found, sizeof(bool), hipMemcpyDeviceToHost));
            if (h_found_local) password_found = true;
        }
    }

    CHECK(hipDeviceSynchronize()); // Attendo terminazione kernel 

    // Recupero risultati finali
    // (Se password_found � true, h_result � gi� stato popolato se trovato col dizionario, 
    // ma se trovato col salt devo copiarlo ora o l'avrei dovuto copiare nel loop. 
    // Per sicurezza faccio una copia finale se d_found � true)

    bool final_found = false;
    CHECK(hipMemcpy(&final_found, d_found, sizeof(bool), hipMemcpyDeviceToHost));

    if (final_found)
    {
        CHECK(hipMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, hipMemcpyDeviceToHost));
        printf("\nStringa Totale (Pass+Salt) trovata: %s\n", h_result);

        char* final_decrypted_pass = NULL;
        int totalLen = strlen(h_result);
        int mySaltLen = strlen(salt);
        int realPassLen = totalLen - mySaltLen;

        if (realPassLen > 0)
        {
            // Controllo se il salt � all'INIZIO
            if (strncmp(h_result, salt, mySaltLen) == 0)
            {
                final_decrypted_pass = (char*)malloc(sizeof(char) * (realPassLen + 1));
                strcpy(final_decrypted_pass, h_result + mySaltLen);
                printf("Schema rilevato: [SALT] + [PASSWORD]\n");
            }
            // Controllo se il salt � alla FINE
            else if (strncmp(h_result + realPassLen, salt, mySaltLen) == 0)
            {
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
    iElaps = cpuSecond() - iStart;
    printf("Tempo GPU: %.4f secondi\n", iElaps);

    // Cleanup
    CHECK(hipFree(d_found));
    CHECK(hipFree(d_result));

    free(charSet);
    return 0;
}
