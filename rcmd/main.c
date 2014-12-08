
#include <Windows.h>
#include "rcmd.h"

#ifdef BUILD_DLL

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}

#else

#ifndef BUILD_LIB

#include <stdio.h>
#include "Xgetopt.h"

static
void
_print_usage()
{
    printf("\nRCMD Usage:\n\n");
    printf("\trcmd.exe [options] -p <port>\n\n");
    printf("\toptions:\n");
    printf("\t\t-s\t\tstart as server\n");
    printf("\t\t-c\t\tstart as client\n");
    printf("\t\t-a <address>\taddress of server (requires -c)");
    printf("\n\n");

}

int main(int argc, char** argv)
{
    int c           = 0;
    char* port      = NULL;
    char* address   = NULL;
    BOOL server     = FALSE;

    while ((c = getopt(argc, argv, "sca:p:")) != EOF)
    {
        switch (c)
        {
            case ('c'):
                server = FALSE;
                break;
            case ('s') :
                server = TRUE;
                break;
            case ('a') :
                address = optarg;
                break;
            case ('p') :
                port = optarg;
                break;
            default:
                break;
        }
    }

    if (NULL == port)
    {
        _print_usage();
    }
    else if (server)
    {
        rcmd_server_start(port);
    }
    else if (NULL != address)
    {
        rcmd_client_start(address, port);
    }
    else
    {
        _print_usage();
    }
}
#endif
#endif
