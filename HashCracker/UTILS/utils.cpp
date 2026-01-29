#include "utils.h"

extern "C" {
    double cpuSecond() {
        struct timespec ts;
        timespec_get(&ts, TIME_UTC);
        return ((double)ts.tv_sec + (double)ts.tv_nsec * 1.e-9);
    }
}

char* leggiCharSet(const char* nomeFile) {
    FILE* file = fopen(nomeFile, "r");
    if (!file) {
        perror("Errore apertura file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long lunghezza = ftell(file);
    rewind(file);

    char* buffer = (char*)malloc((lunghezza + 1) * sizeof(char));
    if (!buffer) {
        perror("Errore allocazione memoria");
        fclose(file);
        return NULL;
    }

    size_t letti = fread(buffer, sizeof(char), lunghezza, file);
    buffer[letti] = '\0'; // aggiunge terminatore di stringa

    fclose(file);
    return buffer;
}

int safe_atoi(const char* str, int* out_val) {
    char* endptr;
    long val;

    errno = 0;
    val = strtol(str, &endptr, 10);

    // controlla se non � stato letto nulla
    if (endptr == str)
        return 0;

    // controlla overflow/underflow
    if ((val > INT_MAX) || (val < INT_MIN))
        return 0;

    // controlla se c�� stato un errore di conversione
    if (errno == ERANGE)
        return 0;

    *out_val = (int)val;
    return 1;
} 

/* 
funzione che si occupa di aggiungere il salt alla password 
potrebbe aggiungerlo in testa o in coda (cambiando l'implementazione di questo metodo) 
*/
char* salt_password(char password[], int passLen, char salt[], int saltLen)
{
    // Alloca spazio per salt + password + il terminatore di stringa '\0'
    char* salted_password = (char*)malloc(sizeof(char) * (saltLen + passLen + 1));

    if (salted_password == NULL) {
        perror("Errore allocazione memoria");
        return NULL;
    }

    memcpy(salted_password, salt, saltLen);
    memcpy(salted_password + saltLen, password, passLen);
    salted_password[saltLen + passLen] = '\0';

    return salted_password;
}


/* 
questa funzione simula il login in un ipotetico database (che conosce il salt e il target_hash). 
prende la password, la concatena con il salt, ne calcola l'hash e lo confronta con il target_hash
*/
int testLogin(char password[], int len, BYTE *target_hash, char salt[])
{
    int result = 0; // 1 se la trovo 
    char* salted_password = salt_password(password,len, salt, strlen(salt));
    
    BYTE hashed_password[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)salted_password, strlen(salted_password), hashed_password);

    if (memcmp(hashed_password, target_hash, SHA256_DIGEST_LENGTH * sizeof(BYTE)) == 0)
    {
        //hash corrisponde
        result = 1; 
    }

    free(salted_password);
    return result;
}

/*funzione che si occupa di linearizzare il dizionario e inserire del padding per avere uno stride 
costante tra le parole*/
char* load_flattened_dictionary(const char* filename, int* outNumWords) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        perror("Errore apertura dizionario");
        return NULL;
    }

    int count = 0;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        int len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            len--;
        }

        if (len > 0) {
            count++;
        }
    }

    if (count == 0) {
        printf("Attenzione: Il dizionario sembra vuoto.\n");
        fclose(f);
        return NULL;
    }

    char* flatDict = (char*)malloc(count * DICT_WORD_LEN * sizeof(char));
    if (!flatDict) {
        perror("Errore malloc dizionario host");
        fclose(f);
        return NULL;
    }

    rewind(f);

    int idx = 0;
    while (fgets(line, sizeof(line), f) && idx < count) {
        int len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0'; 
            len--;
        }

        if (len == 0) continue;

        if (len >= DICT_WORD_LEN) {
            len = DICT_WORD_LEN - 1;
            line[len] = '\0';
        }

        char* dest = &flatDict[idx * DICT_WORD_LEN];

        memset(dest, 0, DICT_WORD_LEN);
        memcpy(dest, line, len);
        idx++;
    }

    fclose(f);
    *outNumWords = idx; 
    return flatDict;
}