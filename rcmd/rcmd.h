
#include <Windows.h>
#pragma comment (lib, "Ws2_32.lib")

#ifdef BUILD_DLL
#define RCMD_EXPORT             __declspec( dllexport ) 
#else
#define RCMD_EXPORT
#endif

#define RCMD_API                __stdcall

#define MAX_CMD_LEN             0x1000

#define RCMD_SUCCESS            0x00000000
#define RCMD_ERR_ARGS           0x00000001
#define RCMD_ERR_INVALID_SOCKET 0x00000002
#define RCMD_ERR_CMD_CREATE     0x00000003
#define RCMD_ERR_CMD_START      0x00000004
#define RCMD_ERR_CMD_EXECUTE    0x00000005
#define RCMD_ERR_SOCKET         0x00000006
#define RCMD_ERR_WSA            0x00000007
#define RCMD_ERR_SOCKET_CREATE  0x00000008
#define RCMD_ERR_SOCKET_BIND    0x00000009
#define RCMD_ERR_SOCKET_LISTEN  0x0000000A
#define RCMD_ERR_ADDR           0x0000000B
#define RCMD_ERR_PIPE           0x0000000C
#define RCMD_ERR_CONNECT        0x0000000D
#define RCMD_ERR_IO_THREADS     0x0000000E

RCMD_EXPORT
ULONG
RCMD_API
rcmd_server_start
(
    PCHAR  port
);


ULONG
RCMD_API
rcmd_client_start
(
    PCHAR   serverIp,
    PCHAR   port
);