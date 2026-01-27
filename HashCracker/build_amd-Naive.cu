/*
 * sha256.cu Implementation of SHA256 Hashing    
 *
 * Date: 12 June 2019
 * Revision: 1
 * *
 * Based on the public domain Reference Implementation in C, by
 * Brad Conte, original code here:
 *
 * https://github.com/B-Con/crypto-algorithms
 *
 * This file is released into the Public Domain.
 */

 
/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <hip/hip_runtime.h>
// #include "device_launch_parameters.h"
#include <time.h>
#include <math.h>
#include <openssl/sha.h>
#include <string.h>
#include "UTILS/utils.h"

typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, importante che sia a 32 bit

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} HIP_SHA256_CTX;

/****************************** MACROS ******************************/
#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
__constant__ WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
__device__  __forceinline__ void hip_sha256_transform(HIP_SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

__device__ void hip_sha256_init(HIP_SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

__device__ void hip_sha256_update(HIP_SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			hip_sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ void hip_sha256_final(HIP_SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		hip_sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	hip_sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

__global__ void kernel_sha256_hash(BYTE* indata, WORD inlen, BYTE* outdata, WORD n_batch)
{
	WORD thread = blockIdx.x * blockDim.x + threadIdx.x;
	if (thread >= n_batch)
	{
		return;
	}
	BYTE* in = indata  + thread * inlen;
	BYTE* out = outdata  + thread * SHA256_BLOCK_SIZE;
	HIP_SHA256_CTX ctx;
	hip_sha256_init(&ctx);
	hip_sha256_update(&ctx, in, inlen);
	hip_sha256_final(&ctx, out);
}

__device__ void dev_sha256(const BYTE* data, WORD len, BYTE* out)
{
	HIP_SHA256_CTX ctx;

	// Inizializzazione del contesto
	hip_sha256_init(&ctx);

	// Hashing dei dati
	hip_sha256_update(&ctx, data, len);

	// Scrittura risultato
	hip_sha256_final(&ctx, out);
}

extern "C"
{
void mcm_hip_sha256_hash_batch(BYTE* in, WORD inlen, BYTE* out, WORD n_batch)
{
	BYTE *hip_indata;
	BYTE *hip_outdata;
	hipMalloc(&hip_indata, inlen * n_batch);
	hipMalloc(&hip_outdata, SHA256_BLOCK_SIZE * n_batch);
	hipMemcpy(hip_indata, in, inlen * n_batch, hipMemcpyHostToDevice);

	WORD thread = 256;
	WORD block = (n_batch + thread - 1) / thread;

	kernel_sha256_hash <<<block, thread>>> (hip_indata, inlen, hip_outdata, n_batch);
	hipMemcpy(out, hip_outdata, SHA256_BLOCK_SIZE * n_batch, hipMemcpyDeviceToHost);
	hipDeviceSynchronize();
	hipError_t error = hipGetLastError();
	if (error != hipSuccess) {
		printf("Error hip sha256 hash: %s \n", hipGetErrorString(error));
	}
	hipFree(hip_indata);
	hipFree(hip_outdata);
}
}





__device__ void idxToString(unsigned long long idx, char* result, int len, char* charset, int charsetLen) {
    // Si riempie la stringa partendo dall'ultimo carattere (destra verso sinistra)
    for (int i = len - 1; i >= 0; i--) {
        // Il resto della divisione indica il carattere (rispetto al charset) 
        int charIndex = idx % charsetLen;

        result[i] = charset[charIndex];

        // Si passa alla posizione successiva (a sinistra)
        idx /= charsetLen;
    }
}

__device__ bool check_hash_match(const unsigned char* hash1, const unsigned char* hash2, int hashLen) {
    // Unroll del loop per massimizzare le prestazioni (opzionale, ma aiuta)
#pragma unroll
    for (int i = 0; i < hashLen; i++) {
        if (hash1[i] != hash2[i]) {
            return false; // Appena trovo un byte diverso, esco
        }
    }
    return true;
}

float bytesToGB(size_t bytes) {
    return (float)bytes / (1024.0f * 1024.0f * 1024.0f);
}

// Funzione per stampare le propriet� di un dispositivo
void printDeviceProperties(int deviceId) {
    hipDeviceProp_t prop;
    hipGetDeviceProperties(&prop, deviceId);

    printf("\n=================================================\n");
    printf("Dispositivo %d: %s\n", deviceId, prop.name);
    printf("\n=================================================\n");

    // 1. Compute Capability
    printf("1. Compute Capability: %d.%d\n", prop.major, prop.minor);

    // 2. Memoria Globale Totale
    printf("2. Memoria Globale Totale: %.2f GB\n", bytesToGB(prop.totalGlobalMem));

    // 3. Numero di Multiprocessori
    printf("3. Numero di Multiprocessori: %d\n", prop.multiProcessorCount);

    // 4. Clock Core
    //printf("4. Clock Core: %d MHz\n", prop.clockRate / 1000);

    // 5. Clock Memoria
    //printf("5. Clock Memoria: %d MHz\n", prop.memoryClockRate / 1000);

    // 6. Larghezza Bus Memoria
    printf("6. Larghezza Bus Memoria: %d bit\n", prop.memoryBusWidth);

    // 7. Dimensione Cache L2
    printf("7. Dimensione Cache L2: %lu KB\n", prop.l2CacheSize / 1024);

    // 8. Memoria Condivisa per Blocco
    printf("8. Memoria Condivisa per Blocco: %lu KB\n", prop.sharedMemPerBlock / 1024);

    // 9. Numero Massimo di Thread per Blocco
    printf("9. Numero Massimo di Thread per Blocco: %d\n", prop.maxThreadsPerBlock);

    // 10. Dimensioni Massime Griglia
    printf("10. Dimensioni Massime Griglia: (%d, %d, %d)\n",
        prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);

    // 11. Dimensioni Massime Blocco
    printf("11. Dimensioni Massime Blocco: (%d, %d, %d)\n",
        prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2]);

    // 12. Warp Size
    printf("12. Warp Size: %d\n", prop.warpSize);

    // 13. Memoria Costante Totale
    printf("13. Memoria Costante Totale: %lu bytes\n", prop.totalConstMem);

    // 14. Texture Alignment
    printf("14. Texture Alignment: %lu bytes\n", prop.textureAlignment);
}

/* dato che 67 ^ 16 � un numero enorme non � tempisticamente possibile provare con numeri maggiori*/
#define MAX_CANDIDATE 16

double cpuSecond() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return ((double)ts.tv_sec + (double)ts.tv_nsec * 1.e-9);
}

double iStart, iElaps;


extern "C" {
    __global__ void bruteForceKernel_Naive(int len, BYTE target_hash[], char *d_charSet, char *d_result, 
        int charSetLen, unsigned long long totalCombinations, bool *d_found)
    {
        unsigned long long idx = (unsigned long long) blockIdx.x * blockDim.x + threadIdx.x;
        unsigned long long stride = (unsigned long long) blockDim.x * gridDim.x;
        char candidate[MAX_CANDIDATE]; 

        while (idx < totalCombinations) {
            // Se qualcun altro ha trovato la password, smetto subito
            if (*d_found) break;

            // Genera la stringa
            idxToString(idx, candidate, len, d_charSet, charSetLen);

            // Calcola Hash 
            BYTE myHash[SHA256_DIGEST_LENGTH];
            dev_sha256((BYTE*)candidate, len, myHash);

            // Controlla risultato
            if (check_hash_match(myHash, target_hash, SHA256_DIGEST_LENGTH)) {
                *d_found = 1;

                candidate[len] = '\0';

                // Copia il risultato per l'host
                for (int i = 0; i <= len; i++) 
                {
                    d_result[i] = candidate[i];
                }

                break;
            }

            idx += stride; 
        }
    }
}


#define CHECK(call) \
{ \
    const hipError_t error = call; \
    if (error != hipSuccess) \
    { \
        printf("Error: %s:%d, ", __FILE__, __LINE__); \
        printf("code: %d, reason: %s\n", error, hipGetErrorString(error)); \
        exit(1); \
    } \
}

#define MAX_CANDIDATE 16

int main(int argc, char** argv)
{
    /*invocazione: ./kernel [password_in_chiaro] [min_len] [max_len] [file_charset] [dizionario si/no] [file_dizionario] */

    //char charSet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#-.\0"; // 67 caratteri
    //char secret_password[] = "qwerty";

    char* charSet, * secret_password;
    int min_test_len, max_test_len;
    bool dizionario = false;

    /* --- CONTROLLO ARGOMENTI DI INVOCAZIONE --- */
    if (argc != 6 && argc != 7) {
        printf("Usage: %s <password_in_chiaro> <min_len> <max_len> <file_charset> <dizionario si/no> [file_dizionario]\n", argv[0]);
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

    if (argv[5][0] == 'S' || argv[5][0] == 's' || argv[5][0] == 'Y' || argv[5][0] == 'y')
    {
        dizionario = true;
    }

    printf("%s Starting...\n", argv[0]);

    //Imposta il device HIP
    int dev = 0;
    printDeviceProperties(dev);
    CHECK(hipSetDevice(dev)); //Seleziona il device HIP

    /* argomenti per invocare le funzioni di hash*/
    unsigned char target_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)secret_password, strlen(secret_password), target_hash);

    printf("\nTarget (segreto): '%s'\n", secret_password);
    printf("Hash Target: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", target_hash[i]);
    printf("\n\n");

    printf("min_test_len %d , max_test_len %d\n", min_test_len, max_test_len);
    printf("CharSet: %s\n", charSet);

    int blockSize = 256;

    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    /* TEST VERSIONE HIP NAIVE */
    /*-----------------------------------------------------------------------------------------------------------------------------------------*/
    printf("--- Inizio Test Brute Force GPU NAIVE ---\n");
    // Allocazione variaibli device
    BYTE* d_target_hash;
    char* d_charSet, * d_result;
    bool* d_found;
    char h_result[MAX_CANDIDATE];

    CHECK(hipMalloc((void**)&d_target_hash, sizeof(BYTE) * SHA256_DIGEST_LENGTH));
    CHECK(hipMemcpy(d_target_hash, target_hash, sizeof(BYTE) * SHA256_DIGEST_LENGTH, hipMemcpyHostToDevice));

    CHECK(hipMalloc((void**)&d_charSet, sizeof(char) * charSetLen));
    CHECK(hipMemcpy(d_charSet, charSet, sizeof(char) * charSetLen, hipMemcpyHostToDevice));

    CHECK(hipMalloc((void**)&d_found, sizeof(bool)));
    CHECK(hipMemset(d_found, false, sizeof(bool)));

    CHECK(hipMalloc((void**)&d_result, MAX_CANDIDATE * sizeof(char)));
    CHECK(hipMemset(d_result, 0, max_test_len * sizeof(char)));

    iStart = cpuSecond();

    for (int len = min_test_len; len <= max_test_len; len++)
    {
        unsigned long long totalCombinations = pow((double)charSetLen, (double)len);
        printf("Controllo kernel naive con lunghezza %d (Combinazioni tot: %llu)...\n", len, totalCombinations);

        unsigned int numBlocks = (totalCombinations + blockSize - 1) / blockSize;

        bruteForceKernel_Naive <<<numBlocks, blockSize>>> (
            len,
            d_target_hash,
            d_charSet,
            d_result,
            charSetLen,
            totalCombinations,
            d_found
            );

            hipError_t err = hipGetLastError();
            if (err != hipSuccess)
                printf("ERRORE LANCIO KERNEL (len %d): %s\n", len, hipGetErrorString(err));
    }

    CHECK(hipDeviceSynchronize()); // Attendo terminazione kernel
    CHECK(hipMemcpy(h_result, d_result, sizeof(char) * MAX_CANDIDATE, hipMemcpyDeviceToHost));
    printf("Password decifrata: %s\n", h_result);

    iElaps = cpuSecond() - iStart;
    printf("Tempo CPU: %.4f secondi\n", iElaps);

    // Deallocazione variaibli device
    CHECK(hipFree(d_charSet));
    CHECK(hipFree(d_target_hash));
    CHECK(hipFree(d_found));
    CHECK(hipFree(d_result));

    free(charSet);

    return 0;
}
