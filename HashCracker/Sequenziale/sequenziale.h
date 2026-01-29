#include <openssl/sha.h> 

/*
* Direttiva necessaria per linking con un progetto HIP ( c++ ) che trasformerebbe il nome della funzioen in un 
* simbolo diverso da quello generato dal compilatore C e quindi non la troverebbe. 
*/
#ifdef __cplusplus
extern "C" {
#endif

    void bruteForceSequenziale(int len, unsigned char target_hash[SHA256_DIGEST_LENGTH], char charSet[], char* result);
    void testSequenziale(unsigned char* target_hash, int min_test_len, int max_test_len, char charSet[]);
    double cpuSecond();

#ifdef __cplusplus
}
#endif

