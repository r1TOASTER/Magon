# Magon: Named Pipes Server and Client

### Please note that Magon is created solely for educational purposes and should not be used for any malicious activities. The project aims to demonstrate inter-process communication and shellcode execution techniques in a controlled and safe environment. Features

    Server and client applications written in C++.
    Communication between the server and client is established using Named Pipes.
    The server passes a shellcode to the client for execution.
    The client injects the shellcode into a hollowed process using ZwUnmapViewOfSection.
    The shellcode is executed from the entry point within the hollowed process.

### Prerequisites

    Windows operating system.
    C++ compiler with C++17 support.
    Basic understanding of inter-process communication and shellcode execution.

### Usage

    Start the MagonServer, and then start the MagonClient.

    The MagonClient will establish a connection with the MagonServer through a Named Pipe.

    The MagonServer will use a pre-defined shellcode (pop calc), then pass it to the MagonClient.

    The MagonClient will suspend an innocent process, hollow it out using ZwUnmapViewOfSection, inject the received shellcode, and execute it from the entry point.

### Disclaimer

Magon is designed and intended for educational purposes only. The project should not be used for any illegal or unethical activities. The creators and contributors of Magon are not responsible for any misuse or damage caused by the use of this software.
License

MIT License
Acknowledgments

This project is inspired by various research and educational resources available on inter-process communication, shellcode execution, and Windows API programming. We extend our gratitude to the authors and contributors of those resources for sharing their knowledge
