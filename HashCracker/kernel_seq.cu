#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "Sequenziale/sequenziale.h"
#include <time.h>
#include <math.h>
#include "UTILS/utils.h"


int main(int argc, char** argv)
{
    /*invocazione: ./kernel <password_in_chiaro> <min_len> <max_len> <file_charset>  */

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;

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
    unsigned char target_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);
    
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    /* TEST VERSIONE SEQUENZIALE */
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    testSequenziale(target_hash, min_test_len, max_test_len, charSet);

    free(charSet);

    return 0;
}
