#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

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

double cpuSecond() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return ((double)ts.tv_sec + (double)ts.tv_nsec * 1.e-9);
}