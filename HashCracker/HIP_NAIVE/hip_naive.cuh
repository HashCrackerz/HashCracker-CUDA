#pragma once
#include <hip/hip_runtime.h>
#include "../SHA256_HIP/sha256.cuh"

extern "C" {
    __global__ void bruteForceKernel_Naive(int len, BYTE target_hash[], char* d_charSet, char* d_result,
        int charSetLen, unsigned long long totalCombinations, bool* d_found);
}