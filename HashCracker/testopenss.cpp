#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main() {
    unsigned char hash[SHA256_DIGEST_LENGTH]; // SHA256_DIGEST_LENGTH = 32 (byte) => 256 bit
    const char* msg = "test";
    SHA256((const unsigned char*)msg, strlen(msg), hash);
        
    printf("SHA256 hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
