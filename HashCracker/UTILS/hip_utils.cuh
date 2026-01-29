#pragma once

#include <hip/hip_runtime.h>
// // // // // #include "device_launch_parameters.h"
#include <stdio.h>
#include "../SHA256_HIP_OPT/config.h"
#include "../HIPv2/hip_v2.cuh"
#include "../UTILS/costanti.h"


__device__ void idxToString(unsigned long long idx, char* result, int len, char* charset, int charsetLen);

__device__ bool check_hash_match(const unsigned char* hash1, const unsigned char* hash2, int hashLen);

void printDeviceProperties(int deviceId);