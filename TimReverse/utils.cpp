#include "utils.h"
#include <Windows.h>
#include <TlHelp32.h>

uintptr_t utils::get_module_base(uint32_t pid, const char* module_name)
{
    HANDLE hProcessModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hProcessModuleSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
    if (!Module32First(hProcessModuleSnap, &me32))
    {
        CloseHandle(hProcessModuleSnap);
        return 0;
    }
    do {
        if (!strcmp(module_name, me32.szModule))
        {
            return (DWORD64)me32.modBaseAddr;
        }
    } while (Module32Next(hProcessModuleSnap, &me32));
    return 0;
}

uint32_t utils::get_process_id(const char* process_name)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    PROCESSENTRY32 pe32;
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return FALSE;
    }
    do {
        if (!strcmp(pe32.szExeFile, process_name))
        {
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    return FALSE;
}

uintptr_t utils::find_pattern(uintptr_t base, size_t size, const char* pattern)
{
    //find pattern utils
    #define InRange(x, a, b) (x >= a && x <= b) 
    #define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
    #define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

    //get module range
    PBYTE ModuleStart = (PBYTE)base;
    PBYTE ModuleEnd = (PBYTE)(ModuleStart + size);

    //scan pattern main
    PBYTE FirstMatch = nullptr;
    const char* CurPatt = pattern;
    for (; ModuleStart < ModuleEnd; ++ModuleStart)
    {
        bool SkipByte = (*CurPatt == '\?');
        if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
            if (!FirstMatch) FirstMatch = ModuleStart;
            SkipByte ? CurPatt += 2 : CurPatt += 3;
            if (CurPatt[-1] == 0) 
                return (ULONG64)FirstMatch;
        }

        else if (FirstMatch) {
            ModuleStart = FirstMatch;
            FirstMatch = nullptr;
            CurPatt = pattern;
        }
    }
    return 0;
}

uintptr_t utils::find_pattern_process(uint32_t pid, uintptr_t base, size_t size, const char* pattern)
{
    HANDLE handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (handle == NULL ||handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    void* buffer = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(handle);
        return 0;
    }
    BOOL flag = ReadProcessMemory(handle, (void*)base, buffer, size, NULL);
    CloseHandle(handle);
    if (!flag)   return 0;

    //find pattern utils
    #define InRange(x, a, b) (x >= a && x <= b) 
    #define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
    #define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

    //get module range
    PBYTE ModuleStart = (PBYTE)buffer;  //先批量读到本进程从本进程匹配
    PBYTE ModuleEnd = (PBYTE)(ModuleStart + size);

    //scan pattern main
    PBYTE FirstMatch = nullptr;
    const char* CurPatt = pattern;
    for (; ModuleStart < ModuleEnd; ++ModuleStart)
    {
        bool SkipByte = (*CurPatt == '\?');
        if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
            if (!FirstMatch) FirstMatch = ModuleStart;
            SkipByte ? CurPatt += 2 : CurPatt += 3;
            if (CurPatt[-1] == 0)
                return base + FirstMatch - (PBYTE)buffer;
        }

        else if (FirstMatch) {
            ModuleStart = FirstMatch;
            FirstMatch = nullptr;
            CurPatt = pattern;
        }
    }
    return 0;
}

bool utils::read_process_memory(uint32_t pid, uintptr_t addr, void* buffer, size_t size)
{
    HANDLE handle = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    BOOL flag = ReadProcessMemory(handle, (void*)addr, buffer, size, NULL);
    CloseHandle(handle);
    return flag;
}

bool utils::write_process_memory(uint32_t pid, uintptr_t addr, void* buffer, size_t size)
{
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    BOOL flag = WriteProcessMemory(handle, (void*)addr, buffer, size, NULL);
    CloseHandle(handle);
    return flag;
}

bool utils::protect_process_memory(uint32_t pid, uintptr_t addr, size_t size, uint32_t prot)
{
    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD oldProt;
    BOOL flag = VirtualProtectEx(handle, (void*)addr, size, prot, &oldProt);
    CloseHandle(handle);
    return flag;
}
