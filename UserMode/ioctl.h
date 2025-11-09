#pragma once
#include <Windows.h>
#include <tlhelp32.h>

//ioctls def
#define ioctl_read_memory             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Read Memory

#define ioctl_write_memory            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Write Memory

#define ioctl_get_module_base         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Get Base Adress

#define ioctl_protect_virutal_memory  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Protect Memory

#define ioctl_allocate_virtual_memory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Allocate Memory

#define ioctl_write_shellcode         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Write Shellcode

#define ioctl_create_thread           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // Create Thread

#define ioctl_find_thread CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

//structs

typedef struct _KFindThreadRequest {
	ULONG pid;
	HANDLE thread_id;
} KFindThreadRequest, * PKFindThreadRequest;

struct KGetBaseModuleRequest {
	ULONG pid;
	ULONGLONG handle;
	WCHAR name[260];
};

struct KRwRequest {
	ULONG pid;
	ULONGLONG src;
	ULONGLONG dst;
	ULONGLONG size;
};

struct KAllocMemRequest {
	ULONG pid, allocation_type, protect;
	ULONGLONG addr;
	SIZE_T size;
};

struct KProtectMemRequest {
	ULONG pid, protect;
	ULONGLONG addr;
	SIZE_T size;
};

struct KCreateThreadRequest {
	ULONG pid;
	ULONGLONG start_address;
	ULONGLONG parameter;
};