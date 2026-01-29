#pragma once
#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include "../UTILS/hip_utils.cuh"
#include "../SHA256_HIP_OPT/sha256_opt.cuh"
#include <stdio.h>
#include "../SHA256_HIP/sha256.cuh"
#include "../SHA256_HIP/config.h"
#include "../UTILS/costanti.h"

extern __constant__ BYTE d_target_hash[SHA256_DIGEST_LENGTH];
extern __constant__ char d_charSet[MAX_CHARSET_LENGTH];

extern "C" {
    __global__ void bruteForceKernel_v2(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found);
}