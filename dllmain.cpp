#include <Windows.h>

void memcopy(BYTE* dst, BYTE* src, size_t size) {
    DWORD oldprotect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldprotect, &oldprotect);
}

namespace mem
{
	template<typename T> T read(uintptr_t address) {
		try { return *(T*)address; }
		catch (...) { return T(); }
	}

	template<typename T> void write(uintptr_t address, T value) {
		try { *(T*)address = value; }
		catch (...) { return; }
	}
}

uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
uintptr_t unlockoffset = 0x0;
void unlock()
{
    uintptr_t num = (base + unlockoffset + 0xC);
    int num2 = mem::read<int>(num);
    uintptr_t unlock_base = num + num2 + 4 - base;
    uintptr_t numP = (base + unlock_base + 0x60);
    DWORD oldprotect;
    memcopy((BYTE*)numP, (BYTE*)"\x48\x83\xC4\x08\x48\x8B\x5C\x24\x30\x48\x8B\x74\x24\x38\x48\x83\xC4\x20\x5F\x48\xC7\xC0\x01\x00\x00\x00\xC3", 28);
    VirtualProtectEx(GetCurrentProcess(), (BYTE*)base + unlock_base, sizeof(base + unlock_base), PAGE_READWRITE, &oldprotect);
    mem::write<uintptr_t>(base + unlock_base + 8, numP);
    mem::write<uintptr_t>(base + unlock_base, base + unlock_base);
    VirtualProtect((BYTE*)base + unlock_base, sizeof(base + unlock_base), oldprotect, &oldprotect);
}

void main()
{
	
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)main, 0, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

