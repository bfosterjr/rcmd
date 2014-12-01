
#include <Windows.h>
#include "cmdlib.h"

typedef enum _CmdStatus
{
    None = 0,
    Created,
    Running,
    Terminated
} CmdStatus;

struct _CMD_HANDLE
{
    HANDLE          hcmdProc;
    HANDLE          hMutex;
    CmdStatus       status;
    HANDLE          hStopEvent;
    ULONG           maxIdleTime;
    HANDLE          keepAlive;

    //input handling
    HANDLE          hInThread;
    HANDLE          hStdIn;
    HANDLE          hInEvent;
    HANDLE          hInMutex;
    PBYTE           inbuf;
    ULONG           inbufLen;

    //output handling
    HANDLE          hOutThread;
    HANDLE          hStdOut;
    HANDLE          hOutEvent;
    OUTPUT_CALLBACK callback_f;
    PVOID           callbackContext;
};

#define DEFAULT_WAIT        5000
#define DEFAULT_PIPE_SIZE   4096 * 2
#define DEFAULT_IDLE_TIME   30000

#define _lock_release(mtx) (void)ReleaseMutex((mtx))

#define CMD_EXE_PATH_A      "%SystemRoot%\\System32\\cmd.exe"


static
BOOL
_lock_acquire
(
    HANDLE  mutex,
    DWORD   timeout
)
{
    DWORD   result = 0;
    BOOL    retVal = FALSE;
    
    result = WaitForSingleObject(mutex, timeout);

    if (WAIT_ABANDONED == result || WAIT_OBJECT_0 == result)
    {
        retVal = TRUE;
    }
    return retVal;
}


#define _close_not_null(hnd) if(NULL != (hnd)) CloseHandle(hnd)
static
BOOL
_create_pipes
(    
    PCMD_HANDLE     pCmdHnd,
    HANDLE          *pStdin,
    HANDLE          *pStdout,
    HANDLE          *pStderr
)
{
    BOOL        retVal      = FALSE;
    HANDLE      stdinRead   = NULL;
    HANDLE      stdinWrite  = NULL;
    HANDLE      stdoutRead  = NULL;
    HANDLE      stdoutWrite = NULL;
    HANDLE      stderr      = NULL;

    HANDLE      inputHnd    = NULL;
    HANDLE      outputHnd   = NULL;

    SECURITY_ATTRIBUTES sa;


    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    __try
    {
        if (!CreatePipe(&stdinRead, &stdinWrite, &sa, DEFAULT_PIPE_SIZE) ||
            !CreatePipe(&stdoutRead, &stdoutWrite, &sa, DEFAULT_PIPE_SIZE))
        {
            //err already set
        }
        else if (!DuplicateHandle(GetCurrentProcess(), stdinWrite, GetCurrentProcess(),
                        &inputHnd, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
                !DuplicateHandle(GetCurrentProcess(), stdoutRead, GetCurrentProcess(),
                        &outputHnd, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
                !DuplicateHandle(GetCurrentProcess(), stdoutWrite, GetCurrentProcess(),
                        &stderr, 0, TRUE, DUPLICATE_SAME_ACCESS))
        {
            //err already set
        }
        else
        {
            *pStdin = stdinRead;
            *pStdout = stdoutWrite;
            *pStderr = stderr;

            pCmdHnd->hStdIn = inputHnd;
            pCmdHnd->hStdOut = outputHnd;

            CloseHandle(stdinWrite);
            stdinWrite = NULL;
            CloseHandle(stdoutRead);
            stdoutRead = NULL;
            retVal = TRUE;
        }
    }
    __finally
    {
        if (!retVal)
        {
            _close_not_null(stdinWrite);
            _close_not_null(stdinRead);
            _close_not_null(stdoutWrite);
            _close_not_null(stdoutRead);
            _close_not_null(stderr);
            _close_not_null(inputHnd);
            _close_not_null(outputHnd);;
        }
    }
    return retVal;
}

static
BOOL
_create_events
(
    PCMD_HANDLE     pCmdHnd
)
{
    BOOL        retVal      = FALSE;
    HANDLE      stopEvent   = NULL;
    HANDLE      inEvent     = NULL;
    HANDLE      outEvent    = NULL;
    HANDLE      keepAlive   = NULL;
    HANDLE      inMutex     = NULL;

    __try
    {
        if (NULL == (inEvent = CreateEventA(NULL, FALSE, FALSE, NULL))  ||
            NULL == (outEvent = CreateEventA(NULL, FALSE, FALSE, NULL)) ||
            NULL == (stopEvent = CreateEventA(NULL, TRUE, FALSE, NULL)) ||
            NULL == (keepAlive = CreateEventA(NULL,FALSE,FALSE,NULL))    ||
            NULL == (inMutex = CreateMutexA(NULL,FALSE,NULL)))
        {
            //err already set
        }
        else
        {
            pCmdHnd->hInEvent = inEvent;
            pCmdHnd->hOutEvent = outEvent;
            pCmdHnd->hStopEvent = stopEvent;
            pCmdHnd->keepAlive = keepAlive;
            pCmdHnd->hInMutex = inMutex;
            retVal = TRUE;
        }
    }
    __finally
    {
        if (!retVal)
        {
            _close_not_null(stopEvent);
            _close_not_null(keepAlive);
            _close_not_null(inEvent);
            _close_not_null(outEvent);
            _close_not_null(inMutex);
        }
    }
    return retVal;
}

static
void
_terminate_cmd
(
    PCMD_HANDLE     pCmdHnd,
    BOOL            cleanInThread
)
{    __try
    {
        if (NULL != pCmdHnd->hStopEvent)
        {
            CloseHandle(pCmdHnd->hStopEvent);
            pCmdHnd->hStopEvent = NULL;
        }

        if (NULL != pCmdHnd->hcmdProc)
        {
            (void)TerminateProcess(pCmdHnd->hcmdProc, 0);
            CloseHandle(pCmdHnd->hcmdProc);
            pCmdHnd->hcmdProc = NULL;
        }

        if (NULL != pCmdHnd->hOutThread)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(pCmdHnd->hOutThread, DEFAULT_WAIT))
            {
                (void)TerminateThread(pCmdHnd->hOutThread, 0);
            }
            CloseHandle(pCmdHnd->hOutThread);
            pCmdHnd->hOutThread = NULL;
        }

        if (NULL != pCmdHnd->hOutEvent)
        {
            CloseHandle(pCmdHnd->hOutEvent);
            pCmdHnd->hOutEvent = NULL;
        }

        if (NULL != pCmdHnd->hStdOut)
        {
            CloseHandle(pCmdHnd->hStdOut);
            pCmdHnd->hStdOut = NULL;
        }

        if (cleanInThread && NULL != pCmdHnd->hInThread)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(pCmdHnd->hInThread, DEFAULT_WAIT))
            {
                (void)TerminateThread(pCmdHnd->hInThread, 0);
            }
            CloseHandle(pCmdHnd->hInThread);
            pCmdHnd->hInThread = NULL;
        }

        if (NULL != pCmdHnd->hStdIn)
        {
            CloseHandle(pCmdHnd->hStdIn);
            pCmdHnd->hStdIn = NULL;
        }

        if (NULL != pCmdHnd->hInMutex)
        {
            CloseHandle(pCmdHnd->hInMutex);
            pCmdHnd->hInMutex = NULL;
        }

        if (NULL != pCmdHnd->hInEvent)
        {
            CloseHandle(pCmdHnd->hInEvent);
            pCmdHnd->hInEvent = NULL;
        }
    }
    __finally
    {

        
    }
}

static
ULONG
_input_thread_f
(
    PVOID   arg
)
{
    PCMD_HANDLE pCmdHnd         = (PCMD_HANDLE) arg;
    BOOL        done            = FALSE;
    HANDLE      waitObjs[5]     = { 0 };
    ULONG       timeout         = 0;
    DWORD       waitRes         = 0;
    DWORD       bytesWritten    = 0;
    BOOL        lock            = FALSE;
    HANDLE      mutex           = NULL;

    __try
    {
        waitObjs[0] = pCmdHnd->hInEvent;
        waitObjs[1] = pCmdHnd->keepAlive;;
        waitObjs[2] = pCmdHnd->hStopEvent;
        waitObjs[3] = pCmdHnd->hcmdProc;
        waitObjs[4] = pCmdHnd->hOutThread;
        timeout = pCmdHnd->maxIdleTime;
        mutex = pCmdHnd->hInMutex;

        while (!done)
        {
            waitRes = WaitForMultipleObjects(5, waitObjs, FALSE, timeout);

            if (1 == (waitRes - WAIT_OBJECT_0))
            {
                continue;
            }
            else if (WAIT_OBJECT_0 != waitRes)
            {
                done = TRUE;
            }
            else if (!(lock = _lock_acquire(mutex, DEFAULT_WAIT)))
            {
                done = TRUE;
            }
            else if (NULL == pCmdHnd->inbuf)
            {
                done = TRUE;
            }
            else
            {
                done = !WriteFile(pCmdHnd->hStdIn, pCmdHnd->inbuf, pCmdHnd->inbufLen, &bytesWritten, NULL);
                (void)HeapFree(GetProcessHeap(), 0, pCmdHnd->inbuf);
                pCmdHnd->inbuf = NULL;
                pCmdHnd->inbufLen = 0;
                _lock_release(mutex);
                lock = FALSE;
            }
        }
    }
    __finally
    {
        if (lock)
        {
            _lock_release(mutex);
            lock = FALSE;
        }

        _terminate_cmd(pCmdHnd, FALSE);

    }

    return 0;
}

static
ULONG
_output_thread_f
(
    PVOID   arg
)
{
    PCMD_HANDLE pCmdHnd     = (PCMD_HANDLE) arg;
    BOOL        done        = FALSE;
    PBYTE       readBuf     = NULL;
    DWORD       bytesRead   = 0;
    BOOL        sent        = FALSE;
    DWORD       lastErr     = 0;

    __try
    {
        while (!done)
        {
            sent = FALSE;
            if (NULL == (readBuf = HeapAlloc(GetProcessHeap(), 0, DEFAULT_PIPE_SIZE)))
            {
                done = TRUE;
            }
            else if (!ReadFile(pCmdHnd->hStdOut, readBuf, DEFAULT_PIPE_SIZE, &bytesRead, NULL))
            {
                lastErr = GetLastError();
                done = TRUE;
            }
            else
            {
                done = !(pCmdHnd->callback_f(pCmdHnd->callbackContext, readBuf, bytesRead));
                sent = TRUE;
                (void)SetEvent(pCmdHnd->hOutEvent);
                (void)SetEvent(pCmdHnd->keepAlive);
            }
        }
        pCmdHnd->callback_f(pCmdHnd->callbackContext, NULL, 0);
        (void)SetEvent(pCmdHnd->hOutEvent);
    }
    __finally
    {
        if (NULL != readBuf && !sent)
        {
           (void) HeapFree(GetProcessHeap(), 0, readBuf);
        }
    }

    return 0;
}

static
BOOL
_create_threads
(
    PCMD_HANDLE     pCmdHnd
)
{
    BOOL    retVal      = FALSE;
    DWORD   threadId    = 0;
    __try
    {
        if (NULL == (pCmdHnd->hOutThread = CreateThread(NULL, 0, _output_thread_f, pCmdHnd, 0, &threadId)) ||
            NULL == (pCmdHnd->hInThread = CreateThread(NULL, 0, _input_thread_f, pCmdHnd, 0, &threadId)))
        {
            //err already set
        }
        else
        {
            retVal = TRUE;
        }
    }
    __finally
    {
        if (!retVal)
        {
            if (NULL != pCmdHnd->hInThread)
            {
                (void)TerminateThread(pCmdHnd->hInThread, 0);
                _close_not_null(pCmdHnd->hInThread);
            }
            if (NULL != pCmdHnd->hOutThread)
            {
                (void)TerminateThread(pCmdHnd->hOutThread, 0);
                _close_not_null(pCmdHnd->hOutThread);
            }
        }
    }
    return retVal;
}

static
BOOL
_create_process
(
    PCMD_HANDLE     pCmdHnd,
    HANDLE          stdin,
    HANDLE          stdout,
    HANDLE          stderr
)
{
    BOOL                    retVal              = FALSE;
    PROCESS_INFORMATION     procInfo            = { 0 };
    STARTUPINFOA            startInfo           = { 0 };
    CHAR                    exePath[MAX_PATH]   = { 0 };

    startInfo.hStdInput = stdin;
    startInfo.hStdOutput = stdout;
    startInfo.hStdError = stderr;
    startInfo.wShowWindow = SW_HIDE;
    startInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    __try
    {
        if (0 == ExpandEnvironmentStringsA(CMD_EXE_PATH_A, exePath, sizeof(exePath) - 1))
        {
            //err already set
        }
        else if (!CreateProcessA(NULL, exePath, NULL, NULL, TRUE, 0, NULL, NULL, &startInfo, &procInfo))
        {
            //err already set
        }
        else
        {
            pCmdHnd->hcmdProc = procInfo.hProcess;
            CloseHandle(procInfo.hThread);
            retVal = TRUE;
        }
    }
    __finally
    {
        if (!retVal)
        {
            if (NULL != procInfo.hProcess)
            {
                (void)TerminateProcess(procInfo.hProcess, 0);
                CloseHandle(procInfo.hProcess);
                CloseHandle(procInfo.hThread);
            }
        }
    }
    return retVal;
}


static
ULONG
_start_cmd
(
    PCMD_HANDLE     pCmdHnd
)
{
    ULONG   retVal  = CMD_START_ERR;
    HANDLE  stdin   = NULL;
    HANDLE  stdout  = NULL;
    HANDLE  stderr  = NULL;

    __try
    {
        if (!_create_pipes(pCmdHnd, &stdin, &stdout, &stderr))
        {
            retVal = CMD_PIPE_ERR;
        }
        else if (!_create_events(pCmdHnd))
        {
            retVal = CMD_EVT_ERR;
        }
        else if (!_create_process(pCmdHnd, stdin, stdout, stderr))
        {
            retVal = CMD_PROC_ERR;
        }
        else if (!_create_threads(pCmdHnd))
        {
            retVal = CMD_THREAD_ERR;
        }
        else
        {
            retVal = CMD_SUCCESS;
        }
    }
    __finally
    {
        if (NULL != stdin)
        {
            CloseHandle(stdin);
        }
        if (NULL != stdout)
        {
            CloseHandle(stdout);
        }
        if (NULL != stderr)
        {
            CloseHandle(stderr);
        }
    }
    return retVal;
}


ULONG
CMD_API
cmd_create
(
    ULONG           maxIdleTime,
    OUTPUT_CALLBACK callback_f,
    PVOID           callbackContext,
    PCMD_HANDLE     *ppCmdHnd
)
{
    ULONG       retVal  = CMD_BAD_ARGS;
    HANDLE      hMutex  = NULL;
    PCMD_HANDLE pCmdHnd = NULL;

    __try
    {
        if (NULL == callback_f || NULL == ppCmdHnd)
        {
            //err already set
        }
        else if (NULL == (pCmdHnd = HeapAlloc(GetProcessHeap(), 0, sizeof(*pCmdHnd))))
        {
            retVal = CMD_NO_MEM;
        }
        else if (NULL == (hMutex = CreateMutex(NULL, TRUE, NULL)))
        {
            retVal = CMD_MUTEX_ERR;
        }
        else
        {

            pCmdHnd->maxIdleTime = (0 == maxIdleTime) ? DEFAULT_IDLE_TIME : maxIdleTime;
            pCmdHnd->callback_f = callback_f;
            pCmdHnd->callbackContext = callbackContext;
            pCmdHnd->status = Created;
            pCmdHnd->hMutex = hMutex;
            pCmdHnd->inbuf = NULL;
            pCmdHnd->inbufLen = 0;
            *ppCmdHnd = pCmdHnd;
            (void)ReleaseMutex(hMutex);
            retVal = CMD_SUCCESS;
        }
    }
    __finally
    {
        if (CMD_SUCCESS != retVal)
        {
            if (NULL != pCmdHnd)
            {
               (void)HeapFree(GetProcessHeap(), 0, pCmdHnd);
               pCmdHnd = NULL;
            }
            if (NULL != hMutex)
            {
                (void)ReleaseMutex(hMutex);
                CloseHandle(hMutex);
            }
        }
    }
    return retVal;
}


ULONG
CMD_API
cmd_destroy
(
    PCMD_HANDLE     *ppCmdHnd
)
{
    ULONG       retVal = CMD_BAD_ARGS;
    BOOL        locked = FALSE;

    __try
    {

        if (NULL == ppCmdHnd || NULL == *ppCmdHnd)
        {
            //err already set
        }
        else if (!(locked = _lock_acquire((*ppCmdHnd)->hMutex, DEFAULT_WAIT)))
        {
            retVal = CMD_LOCK_ERR;
        }
        else if (Terminated != (*ppCmdHnd)->status)
        {
            retVal = CMD_NOT_STOPPED;
        }
        else
        {
            CloseHandle((*ppCmdHnd)->hMutex);
            (void)HeapFree(GetProcessHeap(), 0, *ppCmdHnd);
            *ppCmdHnd = NULL;
            retVal = CMD_SUCCESS;
        }
    }
    __finally
    {
        if (CMD_SUCCESS!= retVal && locked)
        {
            _lock_release((*ppCmdHnd)->hMutex);
            locked = FALSE;
        }

    }
    return retVal;
}


ULONG
CMD_API
cmd_start
(
    PCMD_HANDLE     pCmdHnd,
    BOOL            waitForOutput
)
{
    ULONG       retVal = CMD_BAD_ARGS;
    ULONG       status = CMD_SUCCESS;
    BOOL        locked = FALSE;

    __try
    {

        if (NULL == pCmdHnd)
        {
            //err already set
        }
        else if (!(locked = _lock_acquire(pCmdHnd->hMutex, DEFAULT_WAIT)))
        {
            retVal = CMD_LOCK_ERR;
        }
        else if (Created != pCmdHnd->status)
        {
            retVal = CMD_NOT_CREATED;
        }
        else if (CMD_SUCCESS != (status = _start_cmd(pCmdHnd)))
        {
            retVal = status;
        }
        else
        {
            pCmdHnd->status = Running;
            retVal = CMD_SUCCESS;
        }

        if (waitForOutput && CMD_SUCCESS == retVal)
        {
            (void)WaitForSingleObject(pCmdHnd->hOutEvent, DEFAULT_WAIT);
        }
    }
    __finally
    {
        if (locked)
        {
            _lock_release(pCmdHnd->hMutex);
            locked = FALSE;
        }

    }
    return retVal;
}

ULONG
CMD_API
cmd_stop
(
    PCMD_HANDLE     pCmdHnd
)
{
    ULONG       retVal = CMD_BAD_ARGS;
    BOOL        locked = FALSE;

    __try
    {

        if (NULL == pCmdHnd)
        {
            //err already set
        }
        else if (!(locked = _lock_acquire(pCmdHnd->hMutex, DEFAULT_WAIT)))
        {
            retVal = CMD_LOCK_ERR;
        }
        else if (Running != pCmdHnd->status)
        {
            retVal = CMD_NOT_RUNNING;
        }
        else if (!SetEvent(pCmdHnd->hStopEvent))
        {
            retVal = CMD_EVT_ERR;
        }
        else if (WAIT_OBJECT_0 != WaitForSingleObject(pCmdHnd->hInThread,DEFAULT_WAIT))
        {
            pCmdHnd->status = None;
            retVal = CMD_WAIT_ERR;
        }
        else
        {
            pCmdHnd->status = Terminated;
            retVal = CMD_SUCCESS;
        }
    }
    __finally
    {
        if (locked)
        {
            _lock_release(pCmdHnd->hMutex);
            locked = FALSE;
        }

    }
    return retVal;
}


ULONG
CMD_API
cmd_execute
(
    PCMD_HANDLE     pCmdHnd,
    PBYTE           pCmd,
    ULONG           cmdLen,
    BOOL            waitForOutput
)
{
    ULONG       retVal = CMD_BAD_ARGS;
    BOOL        locked = FALSE;
    BOOL        inLock = FALSE;
    PBYTE       inBuf  = NULL;

    __try
    {

        if (NULL == pCmdHnd || NULL == pCmd || 0 == cmdLen)
        {
            //err already set
        }
        else if (NULL == (inBuf = HeapAlloc(GetProcessHeap(), 0, cmdLen)) ||
                (CopyMemory(inBuf,pCmd,cmdLen), FALSE) )
        {
            retVal = CMD_NO_MEM;
        }
        else if (!(locked = _lock_acquire(pCmdHnd->hMutex, DEFAULT_WAIT)))
        {
            retVal = CMD_LOCK_ERR;
        }
        else if (Running != pCmdHnd->status)
        {
            retVal = CMD_NOT_RUNNING;
        }
        else if (!(inLock = _lock_acquire(pCmdHnd->hInMutex, DEFAULT_WAIT)))
        {
            retVal = CMD_LOCK_ERR;
        }
        else if (NULL != pCmdHnd->inbuf)
        {
            retVal = CMD_INPUT_ERR;
        }
        else if (!SetEvent(pCmdHnd->hInEvent))
        {
            retVal = CMD_EVT_ERR;
        }
        else
        {
            pCmdHnd->inbuf = inBuf;
            pCmdHnd->inbufLen = cmdLen;
            _lock_release(pCmdHnd->hInMutex);
            inLock = FALSE;
            retVal = CMD_SUCCESS;
        }

        if (waitForOutput && CMD_SUCCESS == retVal)
        {
            (void)WaitForSingleObject(pCmdHnd->hOutEvent, DEFAULT_WAIT);
        }
    }
    __finally
    {
        if (CMD_SUCCESS != retVal && NULL == inBuf)
        {
            HeapFree(GetProcessHeap(), 0, inBuf);
        }
        if (inLock)
        {
            _lock_release(pCmdHnd->hInMutex);
            inLock = FALSE;
        }
        if (locked)
        {
            _lock_release(pCmdHnd->hMutex);
            locked = FALSE;
        }

    }
    return retVal;
}
