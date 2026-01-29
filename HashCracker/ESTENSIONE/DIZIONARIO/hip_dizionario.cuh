#pragma once
#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include "../../UTILS/hip_utils.cuh"
#include "../../SHA256_HIP_OPT/sha256_opt.cuh"
#include <stdio.h>
#include "../../UTILS/costanti.h" 

extern __constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
extern __constant__ char d_charSet[MAX_CHARSET_LENGTH];

// Kernel
extern "C" {
    __global__ void bruteForceKernel_dizionario(char* d_dictionary, int numWords, int saltLen,
        int charSetLen, unsigned long long totalSalts,char* d_result, bool* d_found);
}