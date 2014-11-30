
#include <Windows.h>

#define CMD_UNKOWN_ERR  0xFFFFFFFF
#define CMD_SUCCESS     0x00000000
#define CMD_BAD_ARGS    0x00000001
#define CMD_NO_MEM      0x00000002
#define CMD_MUTEX_ERR   0x00000003
#define CMD_LOCK_ERR    0x00000004
#define CMD_START_ERR   0x00000005
#define CMD_PIPE_ERR    0x00000006
#define CMD_EVT_ERR     0x00000007
#define CMD_THREAD_ERR  0x00000008
#define CMD_PROC_ERR    0x00000009
#define CMD_WAIT_ERR    0x0000000A
#define CMD_NOT_RUNNING 0x0000000B
#define CMD_NOT_STOPPED 0x0000000C
#define CMD_NOT_CREATED 0x0000000D
#define CMD_INPUT_ERR   0x0000000E

#ifdef BUILD_DLL
    #define CMD_EXPORT           __declspec( dllexport ) 
#else
    #define CMD_EXPORT
#endif

#define CMD_API                 __stdcall

typedef BOOL(CMD_API *OUTPUT_CALLBACK)(PVOID context, PBYTE output, ULONG outputLen);

typedef struct _CMD_HANDLE CMD_HANDLE, *PCMD_HANDLE;

#define cmd_free_output(buf) HeapFree(GetProcessHeap(),0,(buf))

CMD_EXPORT
ULONG
CMD_API
cmd_create
(
    ULONG           maxIdleTime,
    OUTPUT_CALLBACK callback_f,
    PVOID           callbackContext,
    PCMD_HANDLE     *ppCmdHnd
);

CMD_EXPORT
ULONG
CMD_API
cmd_destroy
(
    PCMD_HANDLE     *ppCmdHnd
);

CMD_EXPORT
ULONG
CMD_API
cmd_start
(
    PCMD_HANDLE     pCmdHnd,
    BOOL            waitForOutput
);

CMD_EXPORT
ULONG
CMD_API
cmd_stop
(
    PCMD_HANDLE     pCmdHnd
);

CMD_EXPORT
ULONG
CMD_API
cmd_execute
(
    PCMD_HANDLE     pCmdHnd,
    PBYTE           pCmd,
    ULONG           cmdLen,
    BOOL            waitForOutput
);


