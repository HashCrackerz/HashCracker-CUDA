#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h> 
#include <openssl/sha.h>
#include "../../UTILS/utils.h"
#include "../../Sequenziale/sequenziale.h"

char* testSequenziale_estensione(unsigned char* target_hash, int min_test_len, int max_test_len, char charSet[], char salt[]);