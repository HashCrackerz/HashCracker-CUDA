#include "sha256_salt.h"

char* testSequenziale_salt(unsigned char* target_hash, int min_test_len, int max_test_len, char charSet[], char salt[]) {
    printf("--- Inizio Test Brute Force CPU ---\n");

    char* result = NULL;
    char found_password[100] = { 0 };

    double iStart, iElaps;
    iStart = cpuSecond();

    for (int len = min_test_len; len <= max_test_len; len++) {
        printf("Tentativo lunghezza %d... ", len);
        fflush(stdout);

        bruteForceSequenziale(len, target_hash, charSet, found_password);

        if (strlen(found_password) > 0) {
            printf("TROVATA!\n");
            printf("Password salted decifrata: %s\n", found_password);
            break;
        }
        else {
            printf("Nessuna corrispondenza.\n");
        }
    }

    /* cerco password e salt splittando la found_password */
    int passLen = strlen(found_password);
    // il salt può essere da 1 a len(password) - 1 caratteri 
    for (int i = 1; i < passLen; i++)
    {
        //test salt all'inizio
        if (testLogin(&found_password[i], passLen - i, target_hash, salt) == 1) 
        {
            int len = passLen - i;
            result = (char*)malloc(sizeof(char) * (len + 1));
            if (result != NULL) 
            {
                memcpy(result, &found_password[i], len);
                result[len] = '\0';
            }
            break;
        }
        //test salt alla fine 
        if (testLogin(found_password, passLen - i, target_hash, salt) == 1) 
        {
            int len = passLen - i;
            result = (char*)malloc(sizeof(char) * (len + 1));
            if (result != NULL)
            {
                memcpy(result, found_password, len);
                result[len] = '\0';
            }
            break;
        }
    }

    // end time 
    iElaps = cpuSecond() - iStart;
    printf("Tempo CPU: %.4f secondi\n", iElaps);

    if (strlen(found_password) == 0) {
        printf("\nPassword non trovata nel range di lunghezza 1-%d.\n", max_test_len);
    }

    return result;
}