#pragma once

#include "../SHA256_CUDA/sha256.cuh"

__global__ void bruteForceKernel_v2(int len, char* d_result, int charSetLen, unsigned long long totalCombinations, bool* d_found);