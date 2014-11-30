#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "rcmd.h"

static
ULONG
__stdcall
_send_thread_f
(
PVOID arg
)
{
    ULONG   retVal          = RCMD_SUCCESS;
    SOCKET  connectSocket   = (SOCKET)arg;
    BOOL    done            = FALSE;
    DWORD   charsRead       = 0;
    CHAR    readBuf[MAX_CMD_LEN];

    do
    {
        done = TRUE;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), readBuf, sizeof(readBuf), &charsRead, NULL))
        {
            retVal = RCMD_ERR_PIPE;
        }
        else if (SOCKET_ERROR == send(connectSocket, readBuf, charsRead, 0))
        {
            shutdown(connectSocket, SD_SEND);
            closesocket(connectSocket);
            retVal = RCMD_ERR_SOCKET;
        }
        else
        {
            done = FALSE;
        }
    } while (!done);

    return retVal;
}


static
ULONG
__stdcall
_recv_thread_f
(
PVOID arg
)
{
    ULONG   retVal          = RCMD_SUCCESS;
    SOCKET  connectSocket   = (SOCKET)arg;
    BOOL    done            = FALSE;
    int     recvSize        = 0;
    DWORD   bytesWritten    = 0;
    CHAR    recvBuf[MAX_CMD_LEN];

    do
    {
        done = TRUE;
        recvSize = recv(connectSocket, recvBuf, sizeof(recvBuf), 0);
        if (0 > recvSize)
        {
            retVal = RCMD_ERR_SOCKET;
        }
        else if (0 == recvSize)
        {
            shutdown(connectSocket, SD_SEND);
            closesocket(connectSocket);
        }
        else
        {
            done = !WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), recvBuf, recvSize, &bytesWritten, NULL);
        }

    } while (!done);

    return retVal;
}

static
BOOL
_create_send_recv_threads
(
    SOCKET connectSocket
)
{
    BOOL    retVal          = FALSE;
    HANDLE  hThreadRecv     = NULL;
    HANDLE  hThreadSend     = NULL;
    HANDLE  wait_objs[2]    = { 0 };
    DWORD   threadId        = 0;


    if (NULL == (hThreadSend = CreateThread(NULL, 0, _send_thread_f, (PVOID)connectSocket, 0, &threadId)) ||
        NULL == (hThreadRecv = CreateThread(NULL, 0, _recv_thread_f, (PVOID)connectSocket, 0, &threadId)))
    {
    }
    else
    {
        wait_objs[0] = hThreadRecv;
        wait_objs[1] = hThreadSend;
        WaitForMultipleObjects(2, wait_objs, TRUE, INFINITE);
        retVal = TRUE;
    }
    return retVal;
}

static
SOCKET
_connect_server
(
    struct addrinfo*  srvinfo
)
{
    SOCKET      connectSocket = INVALID_SOCKET;

    
    for (; srvinfo != NULL; srvinfo = srvinfo->ai_next) {

        // Create a SOCKET for connecting to server
        if (INVALID_SOCKET == (connectSocket = socket(srvinfo->ai_family,
                                srvinfo->ai_socktype, srvinfo->ai_protocol)))
        {
            break;
        }
        else if (SOCKET_ERROR == connect(connectSocket, srvinfo->ai_addr, 
                                        (int)srvinfo->ai_addrlen))
        {
            closesocket(connectSocket);
            connectSocket = INVALID_SOCKET;
        }
        else
        {
            break;
        }
    }

    return connectSocket;
}

ULONG
RCMD_API
rcmd_client_start
(
    PCHAR   serverIp,
    PCHAR   port
)
{
    ULONG           retVal          = RCMD_SUCCESS;
    WSADATA         wsaData         = { 0 };
    SOCKET          connectSocket   = INVALID_SOCKET;
    BOOL            startup         = FALSE;
    struct addrinfo *result         = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    __try
    {
        if (NULL == serverIp || 0 == port)
        {
            retVal = RCMD_ERR_ARGS;
        }
        else if (0 != WSAStartup(MAKEWORD(2, 2), &wsaData) ||
            ((startup = TRUE), FALSE))
        {
            retVal = RCMD_ERR_WSA;
        }
        else if (0 != getaddrinfo(serverIp, port, &hints, &result))
        {
            retVal = RCMD_ERR_ADDR;
        }
        else if (INVALID_SOCKET == (connectSocket = _connect_server(result)))
        {
            retVal = RCMD_ERR_CONNECT;
        }
        else if (!_create_send_recv_threads(connectSocket))
        {
            retVal = RCMD_ERR_IO_THREADS;
        }

    }
    __finally
    {
        if (INVALID_SOCKET != connectSocket)
        {
            shutdown(connectSocket, SD_SEND);
            closesocket(connectSocket);
        }
        if (startup)
        {
            WSACleanup();
        }
    }
    return retVal;
}
