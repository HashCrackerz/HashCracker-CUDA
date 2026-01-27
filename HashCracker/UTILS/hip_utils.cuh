#pragma once

__device__ void idxToString(unsigned long long idx, char* result, int len, char* charset, int charsetLen);

__device__ bool check_hash_match(const unsigned char* hash1, const unsigned char* hash2, int hashLen);

void printDeviceProperties(int deviceId);