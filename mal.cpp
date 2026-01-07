// #include <windows.h>
// #include <iostream>

// // These strings are NEVER executed — only stored in the binary
// const char* suspicious_url = "http://example.com/update";
// const char* suspicious_ip  = "192.168.1.100";
// const char* reg_path       = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
// const char* cmd_string     = "cmd.exe /c echo Hello";
// const char* ps_string      = "powershell -enc AAAA";

// // Dynamic API resolution (often flagged heuristically)
// typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

// int main() {
//     std::cout << "This program does nothing malicious." << std::endl;
//     std::cout << "It only demonstrates static heuristic indicators." << std::endl;

//     // Load a DLL dynamically (common heuristic flag)
//     HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
//     if (hKernel32) {
//         LPFN_ISWOW64PROCESS fnIsWow64 =
//             (LPFN_ISWOW64PROCESS)GetProcAddress(hKernel32, "IsWow64Process");

//         if (fnIsWow64) {
//             BOOL isWow64 = FALSE;
//             fnIsWow64(GetCurrentProcess(), &isWow64);
//         }
//         FreeLibrary(hKernel32);
//     }

//     // Print strings so compiler doesn't optimize them away
//     std::cout << suspicious_url << std::endl;
//     std::cout << suspicious_ip << std::endl;
//     std::cout << reg_path << std::endl;
//     std::cout << cmd_string << std::endl;
//     std::cout << ps_string << std::endl;

//     return 0;
// }


#include <iostream>

volatile const char* a = "OpenProcess";
volatile const char* b = "VirtualAllocEx";
volatile const char* c = "WriteProcessMemory";
volatile const char* d = "CreateRemoteThread";

volatile const char* e = "cmd.exe";
volatile const char* f = "powershell.exe";

volatile const char* g = "IsDebuggerPresent";
volatile const char* h = "NtQueryInformationProcess";

int main() {
    std::cout << "test" << std::endl;
    return 0;
}

