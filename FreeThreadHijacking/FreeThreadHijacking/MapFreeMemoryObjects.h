#include <iostream>
#include <string>
#include <Shlwapi.h>
#include <Psapi.h>
#include <stdio.h>
#include <deque>
#include "resolve.h"


#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2


using namespace std;

class MapMemoryObjects {
public:
    struct MemoryHandlerStruct {
        char HandleType[256];
        uintptr_t HandleAddress;
        uintptr_t HandleValue;
        char HandleAccess[256];
        char ProcessName[256];
        int ProcessID;
    };

    MapMemoryObjects() {

    };

    PSYSTEM_HANDLE_INFORMATION MapMemoryHandlers() {
        NtQuerySystemInformation_t pNtQuerySystemInformation = NULL;
        NTSTATUS status;
        ULONG handleInfoSize = 0x10000;
        PSYSTEM_HANDLE_INFORMATION handleInfo;

        // Resolve NtQuerySystemInformation, NtDuplicateObject, NtQueryObject
        pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");


        // Allocate memory for handle information
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

        while (status = pNtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL) == STATUS_INFO_LENGTH_MISMATCH) {
            handleInfoSize *= 2;
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize);
        }

        return handleInfo;
    }

    deque<HANDLE> FilterFile(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"File") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterRegisterKeys(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Key") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterProcesses(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Process") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterTokens(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Token") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }

    deque<HANDLE> FilterThreads(PSYSTEM_HANDLE_INFORMATION memoryHandlers) {
        deque<HANDLE> processesHandlers;
        NtDuplicateObject_t pNtDuplicateObject = NULL;
        NtQueryObject_t pNtQueryObject = NULL;
        pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");
        ULONG i;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        PVOID objectNameInfo;
        ULONG returnLength;
        UNICODE_STRING objectName;
        HANDLE duplicatedHandle = NULL;
        cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
        cout << "------------" << "\t" << "----------" << "\t" << "------------" << "\t" << "-------------" << "\t" << "-----------" << "\t" << endl;

        for (i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            //printf_s("0x%x\n", memoryHandlers->Handles[i].HandleValue);
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            NTSTATUS status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);


            if (wcscmp(objectTypeInfo->Name.Buffer, L"Thread") == 0) {
                processesHandlers.push_back(duplicatedHandle);
                //         cout << "Process Name" << "\t" << "Process ID" << "\t" << "Handle Value" << "\t" << "Granted Access" << "\t" << "Handle Type" << "\t" << endl;
                printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S\n",
                    "process name",
                    GetProcessId(hProcess),
                    handle.HandleValue,
                    handle.Object,
                    handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
            }
        }
        return processesHandlers;
    }


    HANDLE FindRegistryKeyHandle(PSYSTEM_HANDLE_INFORMATION memoryHandlers, const wstring& registryName) {
        NtDuplicateObject_t pNtDuplicateObject = (NtDuplicateObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDuplicateObject");
        NtQueryObject_t pNtQueryObject = (NtQueryObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryObject");

        POBJECT_TYPE_INFORMATION objectTypeInfo;
        NTSTATUS status;
        HANDLE hProcess;
        HANDLE duplicatedHandle = NULL;

        for (ULONG i = 0; i < memoryHandlers->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = memoryHandlers->Handles[i];
            if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
                continue;
            }

            status = pNtDuplicateObject(hProcess, (void*)handle.HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
            ULONG returnLength;
            status = pNtQueryObject(duplicatedHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, &returnLength);
            if (!NT_SUCCESS(status)) {
                CloseHandle(hProcess);
                continue;
            }

            // Compare with registryName
            if (wcscmp(objectTypeInfo->Name.Buffer, L"Key") == 0) {
                // Now fetch the name of the key
                status = pNtQueryObject(duplicatedHandle, ObjectNameInformation, objectTypeInfo, 0x1000, &returnLength);
                if (NT_SUCCESS(status)) {
                    wstring objectName(objectTypeInfo->Name.Buffer, objectTypeInfo->Name.Length / sizeof(WCHAR));
                    if (objectName == registryName) {
                        CloseHandle(hProcess);
                        return duplicatedHandle;
                    }
                }
            }

            CloseHandle(hProcess);
        }

        return nullptr; // Return nullptr if not found
    }



};
