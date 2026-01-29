#pragma once

#define MAX_CHARSET_LENGTH 67 
#ifndef MAX_CANDIDATE
#define MAX_CANDIDATE 68 // 64 di parola del dizionario + 4 di salt
#endif
#define MAX_SALT_LENGTH 4
#define SHA256_DIGEST_LENGTH    32
#define DICT_WORD_LEN 64 //per l'utilizzo del file "rockyou_trimmed.txt" in cui tutte le parole sono al massimo 64 caratteri 


typedef unsigned char BYTE;
typedef unsigned int  WORD;
typedef unsigned long long LONG;

