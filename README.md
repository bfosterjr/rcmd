# RCMD #

----------

RCMD is a simple remote command shell application which can act as both the client or the server. It works by simply spawning a command shell on the remote machine and manging the STDIN/STDOUT pipes. Much of the inspiration for this code comes straight from the MSDN example.

See: [http://msdn.microsoft.com/en-us/library/windows/desktop/ms682499(v=vs.85).aspx](http://msdn.microsoft.com/en-us/library/windows/desktop/ms682499(v=vs.85).aspx)

RCMD can be built as a standalone application, DLL, or as a static library to be used in other applications.

## Platforms ##

RCMD builds using VS2013 and is supported on all x86, x64, and ARM Windows versions (binaries provided)

## Usage ##

        rcmd.exe [options] -p <port>

        options:
                -s              start as server
                -c              start as client
                -a <address>    address of server (requires -c)

## Example ##

Server:

    rcmd.exe -s -p 8888

Client:

    rcmd.exe -c -a localhost -p 8888