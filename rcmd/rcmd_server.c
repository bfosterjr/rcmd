#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "rcmd.h"
#include "..\cmdlib\cmdlib.h"


static
BOOL
__stdcall
_send_output_f
(
    PVOID context,
    PBYTE output,
    ULONG outputLen
)
{
    BOOL    retVal = FALSE;
    INT     bytesSent = 0;
    SOCKET  clientSocket = (SOCKET)context;

    
    if (NULL == output)
    {
        //err already set
        (void)shutdown(clientSocket, SD_SEND);
    }
    else if (SOCKET_ERROR == (bytesSent = send(clientSocket, output, outputLen, 0)) )
    {
        //err already set
        (void)shutdown(clientSocket, SD_SEND);
    }
    else
    {
        retVal = TRUE;
    }

    cmd_free_output(output);

    return retVal;
}


static
ULONG
_handle_client
(
SOCKET  clientSocket
)
{
    ULONG       retVal              = RCMD_SUCCESS;
    ULONG       cmdStatus           = CMD_SUCCESS;
    INT         bytesRecv           = 0;
    ULONG       cmdLen              = 0;
    BYTE        cmd[MAX_CMD_LEN]    = { 0 };
    PCMD_HANDLE pCmdHnd             = NULL;

    __try
    {

        if (CMD_SUCCESS != cmd_create(0, _send_output_f, (PVOID) clientSocket, &pCmdHnd))
        {
            retVal = RCMD_ERR_CMD_CREATE;
        }
        else if (CMD_SUCCESS != cmd_start(pCmdHnd, TRUE))
        {
            retVal = RCMD_ERR_CMD_START;
        }
        else
        {
            do
            {
                retVal = RCMD_SUCCESS;
                bytesRecv = 0;
                cmdStatus = CMD_SUCCESS;
                ZeroMemory(cmd, sizeof(cmd));

                if (0 == (bytesRecv = recv(clientSocket, (PCHAR)&cmd, sizeof(cmd), 0)))
                {

                }
                else if (0 > bytesRecv)
                {
                    retVal = RCMD_ERR_SOCKET;
                }
                else
                {
                    cmdStatus = cmd_execute(pCmdHnd, cmd, bytesRecv, TRUE);
                    retVal = (CMD_SUCCESS == cmdStatus) ? RCMD_SUCCESS : RCMD_ERR_CMD_EXECUTE;
                }

            } while (bytesRecv > 0 && CMD_SUCCESS == cmdStatus);
        }
    }
    __finally
    {
        if (NULL != pCmdHnd)
        {
            cmd_stop(pCmdHnd);
            cmd_destroy(&pCmdHnd);
        }

        (void)shutdown(clientSocket, SD_SEND);
        closesocket(clientSocket);
    }

    return retVal;
}



static
ULONG
_do_accept
(
    SOCKET          listenSocket
)
{
    ULONG   retVal          = RCMD_SUCCESS;
    SOCKET  clientSocket    = INVALID_SOCKET;

    do
    {
        if (INVALID_SOCKET == (clientSocket = accept(listenSocket, NULL, NULL)))
        {
            retVal = RCMD_ERR_INVALID_SOCKET;
        }
        else
        {
            retVal = _handle_client(clientSocket);
        }
    } while (RCMD_SUCCESS == retVal);

    return retVal;
}



ULONG
RCMD_API
rcmd_server_start
(
    PCHAR  port
)
{
    ULONG           retVal          = RCMD_SUCCESS;
    WSADATA         wsaData         = { 0 };
    SOCKET          listenSocket    = INVALID_SOCKET;
    BOOL            startup         = FALSE;
    struct addrinfo *result         = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    __try
    {
        if (NULL == port)
        {
            retVal = RCMD_ERR_ARGS;
        }
        else if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData) ||
            ((startup = TRUE),FALSE) )
        {
            retVal = RCMD_ERR_WSA;
        }
        else if (0 != getaddrinfo(NULL, port, &hints, &result))
        {
            retVal = RCMD_ERR_ADDR;
        }
        else if (INVALID_SOCKET == (listenSocket = socket(result->ai_family,
            result->ai_socktype, result->ai_protocol)))
        {
            retVal = RCMD_ERR_SOCKET_CREATE;
        }
        else if (SOCKET_ERROR == bind(listenSocket, result->ai_addr, (int)result->ai_addrlen))
        {
            retVal = RCMD_ERR_SOCKET_BIND;
        }
        else if (SOCKET_ERROR == listen(listenSocket, SOMAXCONN))
        {
            retVal = RCMD_ERR_SOCKET_LISTEN;
        }
        else
        {
            retVal = _do_accept(listenSocket);
        }
    }
    __finally
    {

        if (NULL != result)
        {
            freeaddrinfo(result);
            result = NULL;
        }

        if (INVALID_SOCKET != listenSocket)
        {
            closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }

        if (startup)
        {
            (void)WSACleanup();
        }
    }
    return retVal;
}
