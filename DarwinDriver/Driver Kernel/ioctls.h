#pragma once
#include "definitions.h"

#define ioctl_read_memory             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Read Memory

#define ioctl_write_memory            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Write Memory

#define ioctl_get_module_base         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Get Base Adress

#define ioctl_protect_virutal_memory  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Protect Memory

#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Allocate Memory

#define ioctl_write_shellcode         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Write Shellcode

#define ioctl_create_thread           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Create Thread



typedef struct _k_get_base_module_request {
    ULONG pid;
    ULONGLONG handle;
    WCHAR name[260];
} k_get_base_module_request, * pk_get_base_module_request;

typedef struct _k_rw_request {
    ULONG pid;
    ULONGLONG src;
    ULONGLONG dst;
    ULONGLONG size;
} k_rw_request, * pk_rw_request;

typedef struct _k_alloc_mem_request {
    ULONG pid, allocation_type, protect;
    ULONGLONG addr;
    SIZE_T size;
} k_alloc_mem_request, * pk_alloc_mem_request;

typedef struct _k_protect_mem_request {
    ULONG pid, protect;
    ULONGLONG addr;
    SIZE_T size;
} k_protect_mem_request, * pk_protect_mem_request;

typedef struct _k_create_thread_request {
    ULONG pid;
    ULONGLONG start_address;
} k_create_thread_request, * pk_create_thread_request;