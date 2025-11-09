#pragma once
#include "driver_com.h"

#include <dwmapi.h>
#include <d3d11.h>


#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <xmmintrin.h>
#include <emmintrin.h>

#define Assert( _exp ) ((void)0)
#define PI 3.14159265358979323846f
#pragma once

#include <ntifs.h>
#include <ntddk.h>

typedef KGetBaseModuleRequest k_get_base_module_request;
typedef KGetBaseModuleRequest* pk_get_base_module_request;

typedef KRwRequest k_rw_request;
typedef KRwRequest* pk_rw_request;

typedef KAllocMemRequest k_alloc_mem_request;
typedef KAllocMemRequest* pk_alloc_mem_request;

typedef KProtectMemRequest k_protect_mem_request;
typedef KProtectMemRequest* pk_protect_mem_request;

typedef KCreateThreadRequest k_create_thread_request;
typedef KCreateThreadRequest* pk_create_thread_request;


inline bool WriteFloat(uintptr_t address, float value) {

    unsigned char buffer[sizeof(float)];
    std::memcpy(buffer, &value, sizeof(float));

    void* unmanagedPointer = std::malloc(sizeof(float));
    if (!unmanagedPointer)
        return false;

    std::memcpy(unmanagedPointer, buffer, sizeof(float));

    bool result = comDriver::WriteMemory(
        reinterpret_cast<uintptr_t>(unmanagedPointer),
        address,
        sizeof(float)
    );

    std::free(unmanagedPointer);
    return result;
}



inline bool WriteByte(uintptr_t address, uint8_t value)
{
    void* unmanagedPointer = std::malloc(sizeof(uint8_t));
    if (!unmanagedPointer)
        return false;

    std::memcpy(unmanagedPointer, &value, sizeof(uint8_t));

    bool result = comDriver::WriteMemory(
        reinterpret_cast<uintptr_t>(unmanagedPointer),
        address,
        sizeof(uint8_t)
    );

    std::free(unmanagedPointer);
    return result;
}

inline uintptr_t ReadUIntPtr(uintptr_t address)
{
    uintptr_t value = 0;

    if (!comDriver::ReadMemory(
        address,
        reinterpret_cast<uintptr_t>(&value),
        sizeof(value)
    ))
    {
        std::cerr << "[-] Failed to read uintptr_t at 0x"
            << std::hex << address << std::dec << std::endl;
        throw std::runtime_error("ReadUIntPtr: DeviceIoControl failed");
    }

    return value;
}

inline float ReadFloat(uintptr_t address)
{
    float value = 0.0f;

    if (!comDriver::ReadMemory(
        address,
        reinterpret_cast<uintptr_t>(&value),
        sizeof(value)
    ))
    {
        std::cerr << "[-] Failed to read float at 0x"
            << std::hex << address << std::dec << std::endl;
        throw std::runtime_error("ReadFloat: DeviceIoControl failed");
    }

    return value;
}

inline uint8_t ReadByte(uintptr_t address)
{
    uint8_t value = 0;

    if (!comDriver::ReadMemory(
        address,
        reinterpret_cast<uintptr_t>(&value),
        sizeof(value)
    ))
    {
        std::cerr << "[-] Failed to read byte at 0x"
            << std::hex << address << std::dec << std::endl;
        throw std::runtime_error("ReadByte: DeviceIoControl failed");
    }

    return value;
}

