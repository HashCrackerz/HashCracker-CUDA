#pragma once

#include "../SHA256_HIP/sha256.cuh"

extern "C" {
    __global__ void bruteForceKernel_v1(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found);
}