#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include "Sequenziale/sequenziale.h"
#include <time.h>
#include <math.h>
#include "UTILS/utils.h"
#include "ESTENSIONE/SALT/sha256_salt.h"
#include "ESTENSIONE/DIZIONARIO/sha256_dizionario.h"


int main(int argc, char** argv)
{
    /*invocazione: ./kernel <password_in_chiaro> <min_len> <max_len> <file_charset> <dizionario si/no> [file_dizionario]*/

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    bool dizionario = false;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc != 8 && argc != 7) {
        printf("Usage: %s  <password_in_chiaro> <min_len> <max_len> <file_charset> <salt> <dizionario si/no> [file_dizionario]\n", argv[0]);
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

    char* salt = argv[5];

    if (argv[6][0] == 'S' || argv[6][0] == 's' || argv[6][0] == 'Y' || argv[6][0] == 'y')
    {
        dizionario = true;
    }

    printf("%s Starting...\n", argv[0]);
    BYTE target_hash[SHA256_DIGEST_LENGTH];
    char* salted_password = salt_password(secret_password, strlen(secret_password), salt, strlen(salt));
    SHA256((const unsigned char*)salted_password, strlen(salted_password), target_hash);
    printf("Salted password da trovare: %s\n", salted_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");
    
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    /* TEST VERSIONE SEQUENZIALE */
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    char* result = NULL;

    if (dizionario) 
    {
        printf("\nAvvio attacco a dizionario\n");
        result = testSequenziale_dizionario(target_hash, strlen(salt), charSet, salt);
    }

    if (result == NULL || !dizionario) 
    {
        printf("\nAttacco a dizionario non disponibile \n");
        result = testSequenziale_salt(target_hash, min_test_len, max_test_len, charSet, salt);
    }
    

    printf("Passoword trovata: %s\n", result);

    free(charSet);
    free(result);
    free(salted_password);

    return 0;
}
