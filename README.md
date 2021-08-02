## Windows

Currently supports only 32bit processes. But it is not a big problem, you can spawn 32bit process on 64bit system:

`\windows\syswow64\cmd.exe`

`tasklist | findstr cmd.exe`

`shellcode_inject.exe PID meter.bin`

