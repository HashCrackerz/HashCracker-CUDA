#pragma once

#include "../../UTILS/utils.h"
#include "../../UTILS/costanti.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* testSequenziale_dizionario(BYTE* target_hash, int saltLen, char* charSet, char* salt);