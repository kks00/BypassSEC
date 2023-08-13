#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "memory.h"

DWORD GetProcessID(LPCTSTR ProcessName) {
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

int main() {
    DWORD targetPid = GetProcessID(L"trgame.exe");
    if (!targetPid) {
        printf("Process Not Found!\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        return 1;
    }

    PDWORD requestedAddress = (PDWORD)0x019BD404;

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQueryEx(hProcess, requestedAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    printf("AllocationBase = %p, RegionSize = %x\n", mbi.AllocationBase, mbi.RegionSize);

    DWORD OldProtect = 0;
    if (!VirtualProtectEx(hProcess, PVOID(mbi.AllocationBase), mbi.RegionSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {
        printf("VirtualProtectEx Failed! Remapping Section..\n");

        if (!memory::RegionIsMappedView(hProcess, PVOID(mbi.AllocationBase), mbi.RegionSize)) {
            printf("Error: %p must be in a memory mapped view.\n", requestedAddress);
            system("pause");
            return 1;
        }

        if (!memory::ViewHasProtectedProtection(hProcess, PVOID(mbi.AllocationBase), mbi.RegionSize, PAGE_EXECUTE_READWRITE)) {
            return 1;
        }

        if (!memory::RemapViewOfSection(hProcess, PVOID(mbi.AllocationBase), mbi.RegionSize, PAGE_EXECUTE_READWRITE)) {
            printf("Error: failed to remap the view at %p.\n", mbi.AllocationBase);
            system("pause");
            return 1;
        }
    }

    system("pause");

    return 0;
}