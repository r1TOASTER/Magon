#include <Windows.h>
#include <iostream>
#include <algorithm>

HANDLE hPipeClient = nullptr;
DWORD dwPipeMode = 0, dwReadBytes = 0;
BOOL bConnected = FALSE, bReceived = FALSE;

const LPCWSTR pipeName = L"\\\\.\\pipe\\MagonServer";
const unsigned int buffSize = 4096;

int main() {

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
    
    // TODO: inject into screenshot "innocent" process 

    /* cleaning up */
    CloseHandle(hPipeClient);

    return 0;
}