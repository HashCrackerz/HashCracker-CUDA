#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <openssl/sha.h>
#include "../SHA256_CUDA _OPT/config.h"

char* leggiCharSet(const char* nomeFile);
int safe_atoi(const char* str, int* out_val);
int testLogin(char password[], int len, BYTE* target_hash, char salt[]);
char* salt_password(char password[], int passLen, char salt[], int saltLen);